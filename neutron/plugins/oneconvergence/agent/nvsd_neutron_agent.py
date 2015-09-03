# Copyright 2014 OneConvergence, Inc. All Rights Reserved.
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

"""NVSD agent code for security group events."""

import socket
import sys
import time

import eventlet
eventlet.monkey_patch()

from oslo_log import log as logging
import oslo_messaging

from neutron.agent.common import ovs_lib
from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.common import config as common_config
from neutron.common import topics
from neutron import context as n_context
from neutron.extensions import securitygroup as ext_sg
from neutron.i18n import _LE, _LI
from neutron.plugins.oneconvergence.lib import config

LOG = logging.getLogger(__name__)


class NVSDAgentRpcCallback(object):

    target = oslo_messaging.Target(version='1.0')

    def __init__(self, context, agent, sg_agent):
        super(NVSDAgentRpcCallback, self).__init__()
        self.context = context
        self.agent = agent
        self.sg_agent = sg_agent

    def port_update(self, context, **kwargs):
        LOG.debug("port_update received: %s", kwargs)
        port = kwargs.get('port')
        # Validate that port is on OVS
        vif_port = self.agent.int_br.get_vif_port_by_id(port['id'])
        if not vif_port:
            return

        if ext_sg.SECURITYGROUPS in port:
            self.sg_agent.refresh_firewall()


class SecurityGroupAgentRpcCallback(sg_rpc.SecurityGroupAgentRpcCallbackMixin):

    target = oslo_messaging.Target(version=sg_rpc.SG_RPC_VERSION)

    def __init__(self, context, sg_agent):
        super(SecurityGroupAgentRpcCallback, self).__init__()
        self.context = context
        self.sg_agent = sg_agent


class NVSDNeutronAgent(object):
    # history
    #   1.0 Initial version
    #   1.1 Support Security Group RPC
    target = oslo_messaging.Target(version='1.1')

    def __init__(self, integ_br, polling_interval):
        super(NVSDNeutronAgent, self).__init__()
        self.int_br = ovs_lib.OVSBridge(integ_br)
        self.polling_interval = polling_interval
        self.setup_rpc()
        self.ports = set()

    def setup_rpc(self):

        self.host = socket.gethostname()
        self.agent_id = 'nvsd-q-agent.%s' % self.host
        LOG.info(_LI("RPC agent_id: %s"), self.agent_id)

        self.topic = topics.AGENT
        self.context = n_context.get_admin_context_without_session()
        self.sg_plugin_rpc = sg_rpc.SecurityGroupServerRpcApi(topics.PLUGIN)
        self.sg_agent = sg_rpc.SecurityGroupAgentRpc(self.context,
                                                     self.sg_plugin_rpc)

        # RPC network init
        # Handle updates from service
        self.callback_oc = NVSDAgentRpcCallback(self.context,
                                                self, self.sg_agent)
        self.callback_sg = SecurityGroupAgentRpcCallback(self.context,
                                                         self.sg_agent)
        self.endpoints = [self.callback_oc, self.callback_sg]
        # Define the listening consumer for the agent
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.SECURITY_GROUP, topics.UPDATE]]
        self.connection = agent_rpc.create_consumers(self.endpoints,
                                                     self.topic,
                                                     consumers)

    def _update_ports(self, registered_ports):
        ports = self.int_br.get_vif_port_set()
        if ports == registered_ports:
            return
        added = ports - registered_ports
        removed = registered_ports - ports
        return {'current': ports,
                'added': added,
                'removed': removed}

    def _process_devices_filter(self, port_info):
        if 'added' in port_info:
            self.sg_agent.prepare_devices_filter(port_info['added'])
        if 'removed' in port_info:
            self.sg_agent.remove_devices_filter(port_info['removed'])

    def daemon_loop(self):
        """Main processing loop for OC Plugin Agent."""

        ports = set()
        while True:
            try:
                port_info = self._update_ports(ports)
                if port_info:
                    LOG.debug("Port list is updated")
                    self._process_devices_filter(port_info)
                    ports = port_info['current']
                    self.ports = ports
            except Exception:
                LOG.exception(_LE("Error in agent event loop"))

            LOG.debug("AGENT looping.....")
            time.sleep(self.polling_interval)


def main():
    common_config.init(sys.argv[1:])
    common_config.setup_logging()

    integ_br = config.AGENT.integration_bridge
    polling_interval = config.AGENT.polling_interval
    agent = NVSDNeutronAgent(integ_br, polling_interval)
    LOG.info(_LI("NVSD Agent initialized successfully, now running... "))

    # Start everything.
    agent.daemon_loop()
