#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
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
# @author: Somik Behera, Nicira Networks, Inc.
# @author: Brad Hall, Nicira Networks, Inc.
# @author: Dan Wendlandt, Nicira Networks, Inc.
# @author: Dave Lapsley, Nicira Networks, Inc.
# @author: Aaron Rosen, Nicira Networks, Inc.

import logging
import sys
import time

from sqlalchemy.ext import sqlsoup

from quantum.agent.linux import ovs_lib
from quantum.common import config as logging_config
from quantum.common import constants
from quantum.openstack.common import cfg
from quantum.plugins.openvswitch.common import config
from quantum.plugins.openvswitch.agent.ovs_quantum_agent import OVSQuantumAgent

logging.basicConfig()
LOG = logging.getLogger(__name__)

# A placeholder for dead vlans.
DEAD_VLAN_TAG = "4095"


class MetaOVSQuantumAgent(OVSQuantumAgent):

    def daemon_loop(self, db_connection_url):
        '''Main processing loop for Non-Tunneling Agent.

        :param options: database information - in the event need to reconnect
        '''
        self.local_vlan_map = {}
        old_local_bindings = {}
        old_vif_ports = {}
        db_connected = False

        while True:
            if not db_connected:
                time.sleep(self.reconnect_interval)
                db = sqlsoup.SqlSoup(db_connection_url)
                db_connected = True
                LOG.info("Connecting to database \"%s\" on %s" %
                         (db.engine.url.database, db.engine.url.host))

            all_bindings = {}
            try:
                flavor_key = db.flavors.network_id
                port_key = db.ports.network_id
                query = db.session.query(db.ports)
                joined = query.join((db.flavors,
                                     flavor_key == port_key))
                where = db.flavors.flavor == 'openvswitch'
                ports = joined.filter(where).all()
            except Exception, e:
                LOG.info("Unable to get port bindings! Exception: %s" % e)
                db_connected = False
                continue

            for port in ports:
                if self.target_v2_api:
                    all_bindings[port.id] = port
                else:
                    all_bindings[port.interface_id] = port

            vlan_bindings = {}
            try:
                flavor_key = db.flavors.network_id
                vlan_key = db.vlan_bindings.network_id
                query = db.session.query(db.vlan_bindings)
                joined = query.join((db.flavors,
                                     flavor_key == vlan_key))
                where = db.flavors.flavor == 'openvswitch'
                vlan_binds = joined.filter(where).all()
            except Exception, e:
                LOG.info("Unable to get vlan bindings! Exception: %s" % e)
                db_connected = False
                continue

            for bind in vlan_binds:
                vlan_bindings[bind.network_id] = bind.vlan_id

            new_vif_ports = {}
            new_local_bindings = {}
            vif_ports = self.int_br.get_vif_ports()
            for p in vif_ports:
                new_vif_ports[p.vif_id] = p
                if p.vif_id in all_bindings:
                    net_id = all_bindings[p.vif_id].network_id
                    new_local_bindings[p.vif_id] = net_id
                else:
                    # no binding, put him on the 'dead vlan'
                    self.int_br.set_db_attribute("Port", p.port_name, "tag",
                                                 DEAD_VLAN_TAG)
                    self.int_br.add_flow(priority=2,
                                         in_port=p.ofport,
                                         actions="drop")

                old_b = old_local_bindings.get(p.vif_id, None)
                new_b = new_local_bindings.get(p.vif_id, None)

                if old_b != new_b:
                    if old_b is not None:
                        LOG.info("Removing binding to net-id = %s for %s"
                                 % (old_b, str(p)))
                        self.port_unbound(p, True)
                        if p.vif_id in all_bindings:
                            all_bindings[p.vif_id].status = (
                                constants.PORT_STATUS_DOWN)
                    if new_b is not None:
                        # If we don't have a binding we have to stick it on
                        # the dead vlan
                        net_id = all_bindings[p.vif_id].network_id
                        vlan_id = vlan_bindings.get(net_id, DEAD_VLAN_TAG)
                        self.port_bound(p, vlan_id)
                        if p.vif_id in all_bindings:
                            all_bindings[p.vif_id].status = (
                                constants.PORT_STATUS_ACTIVE)
                        LOG.info(("Adding binding to net-id = %s "
                                  "for %s on vlan %s") %
                                 (new_b, str(p), vlan_id))

            for vif_id in old_vif_ports:
                if vif_id not in new_vif_ports:
                    LOG.info("Port Disappeared: %s" % vif_id)
                    if vif_id in old_local_bindings:
                        old_b = old_local_bindings[vif_id]
                        self.port_unbound(old_vif_ports[vif_id], False)
                    if vif_id in all_bindings:
                        all_bindings[vif_id].status = (
                            constants.PORT_STATUS_DOWN)

            old_vif_ports = new_vif_ports
            old_local_bindings = new_local_bindings
            try:
                db.commit()
            except Exception, e:
                LOG.info("Unable to commit to database! Exception: %s" % e)
                db.rollback()
                old_local_bindings = {}
                old_vif_ports = {}

            time.sleep(self.polling_interval)


def main():
    cfg.CONF(args=sys.argv, project='quantum')

    # (TODO) gary - swap with common logging
    logging_config.setup_logging(cfg.CONF)

    # Determine which agent type to use.
    enable_tunneling = cfg.CONF.OVS.enable_tunneling
    integ_br = cfg.CONF.OVS.integration_bridge
    db_connection_url = cfg.CONF.DATABASE.sql_connection
    polling_interval = cfg.CONF.AGENT.polling_interval
    reconnect_interval = cfg.CONF.DATABASE.reconnect_interval
    root_helper = cfg.CONF.AGENT.root_helper

    # Determine API Version to use
    target_v2_api = cfg.CONF.AGENT.target_v2_api

    # Get parameters for OVSQuantumAgent.
    plugin = MetaOVSQuantumAgent(integ_br, root_helper, polling_interval,
                                 reconnect_interval, target_v2_api)

    # Start everything.
    plugin.daemon_loop(db_connection_url)

    sys.exit(0)

if __name__ == "__main__":
    main()
