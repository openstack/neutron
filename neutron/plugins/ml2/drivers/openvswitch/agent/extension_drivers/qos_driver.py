# Copyright (c) 2015 Openstack Foundation
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

from oslo_config import cfg
from oslo_log import log as logging

from neutron.agent.common import ovs_lib
from neutron.agent.l2.extensions import qos_agent
from neutron.extensions import qos

LOG = logging.getLogger(__name__)


class QosOVSAgentDriver(qos_agent.QosAgentDriver):

    def __init__(self):
        super(QosOVSAgentDriver, self).__init__()
        # TODO(QoS) check if we can get this configuration
        #  as constructor arguments
        self.br_int_name = cfg.CONF.OVS.integration_bridge
        self.br_int = None
        self.handlers = {}

    def initialize(self):
        self.handlers[('update', qos.RULE_TYPE_BANDWIDTH_LIMIT)] = (
            self._update_bw_limit_rule)
        self.handlers[('create', qos.RULE_TYPE_BANDWIDTH_LIMIT)] = (
            self._update_bw_limit_rule)
        self.handlers[('delete', qos.RULE_TYPE_BANDWIDTH_LIMIT)] = (
            self._delete_bw_limit_rule)

        self.br_int = ovs_lib.OVSBridge(self.br_int_name)

    def create(self, port, rules):
        self._handle_rules('create', port, rules)

    def update(self, port, rules):
        self._handle_rules('update', port, rules)

    def delete(self, port, rules):
        self._handle_rules('delete', port, rules)

    def _handle_rules(self, action, port, rules):
        for rule in rules:
            handler = self.handlers.get((action, rule.get('type')))
            if handler is not None:
                handler(port, rule)

    def _update_bw_limit_rule(self, port, rule):
        port_name = port.get('name')
        max_kbps = rule.get('max_kbps')
        max_burst_kbps = rule.get('max_burst_kbps')

        current_max_kbps, current_max_burst = (
            self.br_int.get_qos_bw_limit_for_port(port_name))
        if current_max_kbps is not None or current_max_burst is not None:
            self.br_int.del_qos_bw_limit_for_port(port_name)

        self.br_int.create_qos_bw_limit_for_port(port_name,
                                                 max_kbps,
                                                 max_burst_kbps)

    def _delete_bw_limit_rule(self, port, rule):
        port_name = port.get('name')
        current_max_kbps, current_max_burst = (
            self.br_int.get_qos_bw_limit_for_port(port_name))
        if current_max_kbps is not None or current_max_burst is not None:
            self.br_int.del_qos_bw_limit_for_port(port_name)
