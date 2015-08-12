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
from neutron.agent.l2.extensions import qos
from neutron.i18n import _LW
from neutron.plugins.ml2.drivers.openvswitch.mech_driver import (
    mech_openvswitch)

LOG = logging.getLogger(__name__)


class QosOVSAgentDriver(qos.QosAgentDriver):

    _SUPPORTED_RULES = (
        mech_openvswitch.OpenvswitchMechanismDriver.supported_qos_rule_types)

    def __init__(self):
        super(QosOVSAgentDriver, self).__init__()
        self.br_int_name = cfg.CONF.OVS.integration_bridge
        self.br_int = None

    def initialize(self):
        self.br_int = ovs_lib.OVSBridge(self.br_int_name)

    def create(self, port, qos_policy):
        self._handle_rules('create', port, qos_policy)

    def update(self, port, qos_policy):
        self._handle_rules('update', port, qos_policy)

    def delete(self, port, qos_policy):
        # TODO(QoS): consider optimizing flushing of all QoS rules from the
        # port by inspecting qos_policy.rules contents
        self._delete_bandwidth_limit(port)

    def _handle_rules(self, action, port, qos_policy):
        for rule in qos_policy.rules:
            if rule.rule_type in self._SUPPORTED_RULES:
                handler_name = ("".join(("_", action, "_", rule.rule_type)))
                handler = getattr(self, handler_name)
                handler(port, rule)
            else:
                LOG.warning(_LW('Unsupported QoS rule type for %(rule_id)s: '
                            '%(rule_type)s; skipping'),
                            {'rule_id': rule.id, 'rule_type': rule.rule_type})

    def _create_bandwidth_limit(self, port, rule):
        self._update_bandwidth_limit(port, rule)

    def _update_bandwidth_limit(self, port, rule):
        port_name = port['vif_port'].port_name
        max_kbps = rule.max_kbps
        max_burst_kbps = rule.max_burst_kbps

        self.br_int.create_egress_bw_limit_for_port(port_name,
                                                    max_kbps,
                                                    max_burst_kbps)

    def _delete_bandwidth_limit(self, port):
        port_name = port['vif_port'].port_name
        self.br_int.delete_egress_bw_limit_for_port(port_name)
