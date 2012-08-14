#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 NEC Corporation.
# Based on ryu/openvswitch agents.
#
# Copyright 2012 Isaku Yamahata <yamahata at private email ne jp>
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
# @author: Ryota MIBU

import logging
import sys
import time
import socket

from quantum.agent.linux import ovs_lib
from quantum.common import config as logging_config
from quantum.common import topics
from quantum.openstack.common import context
from quantum.openstack.common import rpc
from quantum.plugins.nec.common import config


logging.basicConfig()
LOG = logging.getLogger(__name__)


class NECQuantumAgent(object):

    def __init__(self, integ_br, root_helper, polling_interval):
        '''Constructor.

        :param integ_br: name of the integration bridge.
        :param root_helper: utility to use when running shell cmds.
        :param polling_interval: interval (secs) to check the bridge.
        '''
        self.int_br = ovs_lib.OVSBridge(integ_br, root_helper)
        self.polling_interval = polling_interval

        self.host = socket.gethostname()
        self.agent_id = 'nec-q-agent.%s' % self.host
        self.datapath_id = "0x%s" % self.int_br.get_datapath_id()

        # RPC network init
        self.context = context.RequestContext('quantum', 'quantum',
                                              is_admin=False)
        self.conn = rpc.create_connection(new=True)

    def update_ports(self, port_added=[], port_removed=[]):
        """RPC to update information of ports on Quantum Server"""
        LOG.info("update ports: added=%s, removed=%s" %
                 (port_added, port_removed))
        try:
            rpc.call(self.context,
                     topics.PLUGIN,
                     {'method': 'update_ports',
                      'args': {'topic': topics.AGENT,
                               'agent_id': self.agent_id,
                               'datapath_id': self.datapath_id,
                               'port_added': port_added,
                               'port_removed': port_removed}})
        except Exception as e:
            LOG.warn("update_ports() failed.")
            return

    def _vif_port_to_port_info(self, vif_port):
        return dict(id=vif_port.vif_id, port_no=vif_port.ofport,
                    mac=vif_port.vif_mac)

    def daemon_loop(self):
        """Main processing loop for NEC Plugin Agent."""
        old_ports = []
        while True:
            new_ports = []

            port_added = []
            for vif_port in self.int_br.get_vif_ports():
                port_id = vif_port.vif_id
                new_ports.append(port_id)
                if port_id not in old_ports:
                    port_info = self._vif_port_to_port_info(vif_port)
                    port_added.append(port_info)

            port_removed = []
            for port_id in old_ports:
                if port_id not in new_ports:
                    port_removed.append(port_id)

            if port_added or port_removed:
                self.update_ports(port_added, port_removed)
            else:
                LOG.debug("No port changed.")

            old_ports = new_ports
            time.sleep(self.polling_interval)


def main():
    config.CONF(args=sys.argv, project='quantum')

    logging_config.setup_logging(config.CONF)

    # Determine which agent type to use.
    integ_br = config.OVS.integration_bridge
    root_helper = config.AGENT.root_helper
    polling_interval = config.AGENT.polling_interval

    agent = NECQuantumAgent(integ_br, root_helper, polling_interval)

    # Start everything.
    agent.daemon_loop()

    sys.exit(0)


if __name__ == "__main__":
    main()
