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
# @author: Akihiro MOTOKI

import socket
import sys
import time

import eventlet

from quantum.agent.linux import ovs_lib
from quantum.agent import rpc as agent_rpc
from quantum.agent import securitygroups_rpc as sg_rpc
from quantum.common import config as logging_config
from quantum.common import constants as q_const
from quantum.common import topics
from quantum import context as q_context
from quantum.extensions import securitygroup as ext_sg
from quantum.openstack.common import log as logging
from quantum.openstack.common import loopingcall
from quantum.openstack.common.rpc import dispatcher
from quantum.openstack.common.rpc import proxy
from quantum.plugins.nec.common import config


LOG = logging.getLogger(__name__)


class NECPluginApi(agent_rpc.PluginApi):
    BASE_RPC_API_VERSION = '1.0'

    def update_ports(self, context, agent_id, datapath_id,
                     port_added, port_removed):
        """RPC to update information of ports on Quantum Server"""
        LOG.info(_("Update ports: added=%(added)s, "
                   "removed=%(removed)s"),
                 {'added': port_added, 'removed': port_removed})
        try:
            self.call(context,
                      self.make_msg('update_ports',
                                    topic=topics.AGENT,
                                    agent_id=agent_id,
                                    datapath_id=datapath_id,
                                    port_added=port_added,
                                    port_removed=port_removed))
        except Exception:
            LOG.warn(_("update_ports() failed."))
            return


class NECAgentRpcCallback(object):

    RPC_API_VERSION = '1.0'

    def __init__(self, context, agent, sg_agent):
        self.context = context
        self.agent = agent
        self.sg_agent = sg_agent

    def port_update(self, context, **kwargs):
        LOG.debug(_("port_update received: %s"), kwargs)
        port = kwargs.get('port')
        # Validate that port is on OVS
        vif_port = self.agent.int_br.get_vif_port_by_id(port['id'])
        if not vif_port:
            return

        if ext_sg.SECURITYGROUPS in port:
            self.sg_agent.refresh_firewall()


class SecurityGroupServerRpcApi(proxy.RpcProxy,
                                sg_rpc.SecurityGroupServerRpcApiMixin):

    def __init__(self, topic):
        super(SecurityGroupServerRpcApi, self).__init__(
            topic=topic, default_version=sg_rpc.SG_RPC_VERSION)


class SecurityGroupAgentRpcCallback(
    sg_rpc.SecurityGroupAgentRpcCallbackMixin):

    RPC_API_VERSION = sg_rpc.SG_RPC_VERSION

    def __init__(self, context, sg_agent):
        self.context = context
        self.sg_agent = sg_agent


class SecurityGroupAgentRpc(sg_rpc.SecurityGroupAgentRpcMixin):

    def __init__(self, context):
        self.context = context
        self.plugin_rpc = SecurityGroupServerRpcApi(topics.PLUGIN)
        self.init_firewall()


class NECQuantumAgent(object):

    def __init__(self, integ_br, root_helper, polling_interval):
        '''Constructor.

        :param integ_br: name of the integration bridge.
        :param root_helper: utility to use when running shell cmds.
        :param polling_interval: interval (secs) to check the bridge.
        '''
        self.int_br = ovs_lib.OVSBridge(integ_br, root_helper)
        self.polling_interval = polling_interval
        self.cur_ports = []

        self.datapath_id = "0x%s" % self.int_br.get_datapath_id()

        self.agent_state = {
            'binary': 'quantum-nec-agent',
            'host': config.CONF.host,
            'topic': q_const.L2_AGENT_TOPIC,
            'configurations': {},
            'agent_type': q_const.AGENT_TYPE_NEC,
            'start_flag': True}

        self.setup_rpc()

    def setup_rpc(self):
        self.host = socket.gethostname()
        self.agent_id = 'nec-q-agent.%s' % self.host
        LOG.info(_("RPC agent_id: %s"), self.agent_id)

        self.topic = topics.AGENT
        self.context = q_context.get_admin_context_without_session()

        self.plugin_rpc = NECPluginApi(topics.PLUGIN)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        self.sg_agent = SecurityGroupAgentRpc(self.context)

        # RPC network init
        # Handle updates from service
        self.callback_nec = NECAgentRpcCallback(self.context,
                                                self, self.sg_agent)
        self.callback_sg = SecurityGroupAgentRpcCallback(self.context,
                                                         self.sg_agent)
        self.dispatcher = dispatcher.RpcDispatcher([self.callback_nec,
                                                    self.callback_sg])
        # Define the listening consumer for the agent
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.SECURITY_GROUP, topics.UPDATE]]
        self.connection = agent_rpc.create_consumers(self.dispatcher,
                                                     self.topic,
                                                     consumers)

        report_interval = config.CONF.AGENT.report_interval
        if report_interval:
            heartbeat = loopingcall.LoopingCall(self._report_state)
            heartbeat.start(interval=report_interval)

    def _report_state(self):
        try:
            # How many devices are likely used by a VM
            num_devices = len(self.cur_ports)
            self.agent_state['configurations']['devices'] = num_devices
            self.state_rpc.report_state(self.context,
                                        self.agent_state)
            self.agent_state.pop('start_flag', None)
        except Exception:
            LOG.exception(_("Failed reporting state!"))

    def _vif_port_to_port_info(self, vif_port):
        return dict(id=vif_port.vif_id, port_no=vif_port.ofport,
                    mac=vif_port.vif_mac)

    def _process_security_group(self, port_added, port_removed):
        if port_added:
            devices_added = [p['id'] for p in port_added]
            self.sg_agent.prepare_devices_filter(devices_added)
        if port_removed:
            self.sg_agent.remove_devices_filter(port_removed)

    def daemon_loop(self):
        """Main processing loop for NEC Plugin Agent."""
        while True:
            new_ports = []

            port_added = []
            for vif_port in self.int_br.get_vif_ports():
                port_id = vif_port.vif_id
                new_ports.append(port_id)
                if port_id not in self.cur_ports:
                    port_info = self._vif_port_to_port_info(vif_port)
                    port_added.append(port_info)

            port_removed = []
            for port_id in self.cur_ports:
                if port_id not in new_ports:
                    port_removed.append(port_id)

            if port_added or port_removed:
                self.plugin_rpc.update_ports(self.context,
                                             self.agent_id, self.datapath_id,
                                             port_added, port_removed)
                self._process_security_group(port_added, port_removed)
            else:
                LOG.debug(_("No port changed."))

            self.cur_ports = new_ports
            time.sleep(self.polling_interval)


def main():
    eventlet.monkey_patch()

    config.CONF(project='quantum')

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
