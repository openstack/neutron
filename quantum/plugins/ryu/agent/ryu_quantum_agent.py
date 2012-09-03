#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 Isaku Yamahata <yamahata at private email ne jp>
# Based on openvswitch agent.
#
# Copyright 2011 Nicira Networks, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
# @author: Isaku Yamahata

import logging as LOG
import sys
import time

from ryu.app import rest_nw_id
from ryu.app.client import OFPClient
from sqlalchemy.ext.sqlsoup import SqlSoup

from quantum.agent.linux import ovs_lib
from quantum.agent.linux.ovs_lib import VifPort
from quantum.common import config as logging_config
from quantum.common import constants
from quantum.openstack.common import cfg
from quantum.plugins.ryu.common import config


class OVSBridge(ovs_lib.OVSBridge):
    def __init__(self, br_name, root_helper):
        ovs_lib.OVSBridge.__init__(self, br_name, root_helper)
        self.datapath_id = None

    def find_datapath_id(self):
        # ovs-vsctl get Bridge br-int datapath_id
        res = self.run_vsctl(["get", "Bridge", self.br_name, "datapath_id"])

        # remove preceding/trailing double quotes
        dp_id = res.strip().strip('"')
        self.datapath_id = dp_id

    def set_controller(self, target):
        methods = ("ssl", "tcp", "unix", "pssl", "ptcp", "punix")
        args = target.split(":")
        if not args[0] in methods:
            target = "tcp:" + target
        self.run_vsctl(["set-controller", self.br_name, target])

    def _vifport(self, name, external_ids):
        ofport = self.db_get_val("Interface", name, "ofport")
        return VifPort(name, ofport, external_ids["iface-id"],
                       external_ids["attached-mac"], self)

    def _get_ports(self, get_port):
        ports = []
        port_names = self.get_port_name_list()
        for name in port_names:
            port = get_port(name)
            if port:
                ports.append(port)

        return ports

    def _get_vif_port(self, name):
        external_ids = self.db_get_map("Interface", name, "external_ids")
        if "iface-id" in external_ids and "attached-mac" in external_ids:
            return self._vifport(name, external_ids)
        elif ("xs-vif-uuid" in external_ids and
              "attached-mac" in external_ids):
            # if this is a xenserver and iface-id is not automatically
            # synced to OVS from XAPI, we grab it from XAPI directly
            ofport = self.db_get_val("Interface", name, "ofport")
            iface_id = self.get_xapi_iface_id(external_ids["xs-vif-uuid"])
            return VifPort(name, ofport, iface_id,
                           external_ids["attached-mac"], self)

    def get_vif_ports(self):
        "returns a VIF object for each VIF port"
        return self._get_ports(self._get_vif_port)

    def _get_external_port(self, name):
        external_ids = self.db_get_map("Interface", name, "external_ids")
        if external_ids:
            return

        ofport = self.db_get_val("Interface", name, "ofport")
        return VifPort(name, ofport, None, None, self)

    def get_external_ports(self):
        return self._get_ports(self._get_external_port)


def check_ofp_mode(db):
    LOG.debug("checking db")

    servers = db.ofp_server.all()

    ofp_controller_addr = None
    ofp_rest_api_addr = None
    for serv in servers:
        if serv.host_type == "REST_API":
            ofp_rest_api_addr = serv.address
        elif serv.host_type == "controller":
            ofp_controller_addr = serv.address
        else:
            LOG.warn("ignoring unknown server type %s", serv)

    LOG.debug("controller %s", ofp_controller_addr)
    LOG.debug("api %s", ofp_rest_api_addr)
    if not ofp_controller_addr:
        raise RuntimeError("OF controller isn't specified")
    if not ofp_rest_api_addr:
        raise RuntimeError("Ryu rest API port isn't specified")

    LOG.debug("going to ofp controller mode %s %s",
              ofp_controller_addr, ofp_rest_api_addr)
    return (ofp_controller_addr, ofp_rest_api_addr)


class OVSQuantumOFPRyuAgent:
    def __init__(self, integ_br, db, root_helper):
        self.root_helper = root_helper
        (ofp_controller_addr, ofp_rest_api_addr) = check_ofp_mode(db)

        self.nw_id_external = rest_nw_id.NW_ID_EXTERNAL
        self.api = OFPClient(ofp_rest_api_addr)
        self._setup_integration_br(integ_br, ofp_controller_addr)

    def _setup_integration_br(self, integ_br, ofp_controller_addr):
        self.int_br = OVSBridge(integ_br, self.root_helper)
        self.int_br.find_datapath_id()
        self.int_br.set_controller(ofp_controller_addr)
        for port in self.int_br.get_external_ports():
            self._port_update(self.nw_id_external, port)

    def _port_update(self, network_id, port):
        self.api.update_port(network_id, port.switch.datapath_id, port.ofport)

    def _all_bindings(self, db):
        """return interface id -> port which include network id bindings"""
        return dict((port.id, port) for port in db.ports.all())

    def _set_port_status(self, port, status):
        port.status = status

    def daemon_loop(self, db):
        # on startup, register all existing ports
        all_bindings = self._all_bindings(db)

        local_bindings = {}
        vif_ports = {}
        for port in self.int_br.get_vif_ports():
            vif_ports[port.vif_id] = port
            if port.vif_id in all_bindings:
                net_id = all_bindings[port.vif_id].network_id
                local_bindings[port.vif_id] = net_id
                self._port_update(net_id, port)
                self._set_port_status(all_bindings[port.vif_id],
                                      constants.PORT_STATUS_ACTIVE)
                LOG.info("Updating binding to net-id = %s for %s",
                         net_id, str(port))
        db.commit()

        old_vif_ports = vif_ports
        old_local_bindings = local_bindings

        while True:
            all_bindings = self._all_bindings(db)

            new_vif_ports = {}
            new_local_bindings = {}
            for port in self.int_br.get_vif_ports():
                new_vif_ports[port.vif_id] = port
                if port.vif_id in all_bindings:
                    net_id = all_bindings[port.vif_id].network_id
                    new_local_bindings[port.vif_id] = net_id

                old_b = old_local_bindings.get(port.vif_id)
                new_b = new_local_bindings.get(port.vif_id)
                if old_b == new_b:
                    continue

                if old_b:
                    LOG.info("Removing binding to net-id = %s for %s",
                             old_b, str(port))
                    if port.vif_id in all_bindings:
                        self._set_port_status(all_bindings[port.vif_id],
                                              constants.PORT_STATUS_DOWN)
                if new_b:
                    if port.vif_id in all_bindings:
                        self._set_port_status(all_bindings[port.vif_id],
                                              constants.PORT_STATUS_ACTIVE)
                    LOG.info("Adding binding to net-id = %s for %s",
                             new_b, str(port))

            for vif_id in old_vif_ports:
                if vif_id not in new_vif_ports:
                    LOG.info("Port Disappeared: %s", vif_id)
                    if vif_id in all_bindings:
                        self._set_port_status(all_bindings[port.vif_id],
                                              constants.PORT_STATUS_DOWN)

            old_vif_ports = new_vif_ports
            old_local_bindings = new_local_bindings
            db.commit()
            time.sleep(2)


def main():
    cfg.CONF(args=sys.argv, project='quantum')

    # (TODO) gary - swap with common logging
    logging_config.setup_logging(cfg.CONF)

    integ_br = cfg.CONF.OVS.integration_bridge
    root_helper = cfg.CONF.AGENT.root_helper
    options = {"sql_connection": cfg.CONF.DATABASE.sql_connection}
    db = SqlSoup(options["sql_connection"])

    LOG.info("Connecting to database \"%s\" on %s",
             db.engine.url.database, db.engine.url.host)
    plugin = OVSQuantumOFPRyuAgent(integ_br, db, root_helper)
    plugin.daemon_loop(db)

    sys.exit(0)


if __name__ == "__main__":
    main()
