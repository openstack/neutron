#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 Cisco Systems, Inc.
# Copyright 2012 NTT MCL, Inc.
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
#
#
# Performs per host Linux Bridge configuration for Quantum.
# Based on the structure of the OpenVSwitch agent in the
# Quantum OpenVSwitch Plugin.
# @author: Sumit Naiksatam, Cisco Systems, Inc.

import logging
import sys
import time

from sqlalchemy.ext.sqlsoup import SqlSoup

from quantum.openstack.common import cfg
from quantum.common import config as logging_config
from quantum.common import constants
from quantum.plugins.linuxbridge.common import config
import quantum.plugins.linuxbridge.agent.linuxbridge_quantum_agent as lb

from quantum.agent.linux import utils

logging.basicConfig()
LOG = logging.getLogger(__name__)

BRIDGE_NAME_PREFIX = "brq"
VLAN_BINDINGS = "vlan_bindings"
PORT_BINDINGS = "port_bindings"


class MetaLinuxBridgeQuantumAgent(lb.LinuxBridgeQuantumAgent):

    def manage_networks_on_host(self, db,
                                old_vlan_bindings,
                                old_port_bindings):
        vlan_bindings = {}
        try:
            flavor_key = db.flavors.network_id
            vlan_key = db.vlan_bindings.network_id
            query = db.session.query(db.vlan_bindings)
            joined = query.join((db.flavors,
                                 flavor_key == vlan_key))
            where = db.flavors.flavor == 'linuxbridge'
            vlan_binds = joined.filter(where).all()
        except Exception as e:
            LOG.info("Unable to get vlan bindings! Exception: %s" % e)
            self.db_connected = False
            return {VLAN_BINDINGS: {},
                    PORT_BINDINGS: []}

        vlans_string = ""
        for bind in vlan_binds:
            entry = {'network_id': bind.network_id, 'vlan_id': bind.vlan_id}
            vlan_bindings[bind.network_id] = entry
            vlans_string = "%s %s" % (vlans_string, entry)

        port_bindings = []
        try:
            flavor_key = db.flavors.network_id
            port_key = db.ports.network_id
            query = db.session.query(db.ports)
            joined = query.join((db.flavors,
                                 flavor_key == port_key))
            where = db.flavors.flavor == 'linuxbridge'
            port_binds = joined.filter(where).all()
        except Exception as e:
            LOG.info("Unable to get port bindings! Exception: %s" % e)
            self.db_connected = False
            return {VLAN_BINDINGS: {},
                    PORT_BINDINGS: []}

        all_bindings = {}
        for bind in port_binds:
            append_entry = False
            if self.target_v2_api:
                all_bindings[bind.id] = bind
                entry = {'network_id': bind.network_id,
                         'uuid': bind.id,
                         'status': bind.status,
                         'interface_id': bind.id}
                append_entry = bind.admin_state_up
            else:
                all_bindings[bind.uuid] = bind
                entry = {'network_id': bind.network_id, 'state': bind.state,
                         'op_status': bind.op_status, 'uuid': bind.uuid,
                         'interface_id': bind.interface_id}
                append_entry = bind.state == constants.PORT_STATUS_ACTIVE
            if append_entry:
                port_bindings.append(entry)

        plugged_interfaces = []
        ports_string = ""
        for pb in port_bindings:
            ports_string = "%s %s" % (ports_string, pb)
            port_id = pb['uuid']
            interface_id = pb['interface_id']

            vlan_id = str(vlan_bindings[pb['network_id']]['vlan_id'])
            if self.process_port_binding(port_id,
                                         pb['network_id'],
                                         interface_id,
                                         vlan_id):
                if self.target_v2_api:
                    all_bindings[port_id].status = constants.PORT_STATUS_ACTIVE
                else:
                    all_bindings[port_id].op_status = (
                        constants.PORT_STATUS_ACTIVE)

            plugged_interfaces.append(interface_id)

        if old_port_bindings != port_bindings:
            LOG.debug("Port-bindings: %s" % ports_string)

        self.process_unplugged_interfaces(plugged_interfaces)

        if old_vlan_bindings != vlan_bindings:
            LOG.debug("VLAN-bindings: %s" % vlans_string)

        self.process_deleted_networks(vlan_bindings)

        try:
            db.commit()
        except Exception as e:
            LOG.info("Unable to update database! Exception: %s" % e)
            db.rollback()
            vlan_bindings = {}
            port_bindings = []

        return {VLAN_BINDINGS: vlan_bindings,
                PORT_BINDINGS: port_bindings}


def main():
    cfg.CONF(args=sys.argv, project='quantum')

    # (TODO)  - swap with common logging
    logging_config.setup_logging(cfg.CONF)

    br_name_prefix = BRIDGE_NAME_PREFIX
    physical_interface = cfg.CONF.LINUX_BRIDGE.physical_interface
    polling_interval = cfg.CONF.AGENT.polling_interval
    reconnect_interval = cfg.CONF.DATABASE.reconnect_interval
    root_helper = cfg.CONF.AGENT.root_helper
    'Establish database connection and load models'
    db_connection_url = cfg.CONF.DATABASE.sql_connection
    plugin = MetaLinuxBridgeQuantumAgent(br_name_prefix, physical_interface,
                                         polling_interval, reconnect_interval,
                                         root_helper,
                                         cfg.CONF.AGENT.target_v2_api)
    LOG.info("Agent initialized successfully, now running... ")
    plugin.daemon_loop(db_connection_url)

    sys.exit(0)

if __name__ == "__main__":
    main()
