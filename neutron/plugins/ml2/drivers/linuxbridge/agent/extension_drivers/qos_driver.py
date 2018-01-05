# Copyright 2016 OVH SAS
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

from neutron_lib import constants as const
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log

from neutron.agent.l2.extensions import qos_linux as qos
from neutron.agent.linux import iptables_manager
from neutron.agent.linux import tc_lib
from neutron.common import ipv6_utils
from neutron.services.qos.drivers.linuxbridge import driver

LOG = log.getLogger(__name__)


class QosLinuxbridgeAgentDriver(qos.QosLinuxAgentDriver):

    # TODO(ralonsoh):
    #   - All driver calls should include the rule parameter, including
    #     the delete function, to have the 'direction' parameter. This QoS
    #     extension modification is going to be implemented in
    #     https://review.openstack.org/#/c/341186/
    SUPPORTED_RULES = driver.SUPPORTED_RULES

    IPTABLES_DIRECTION = {const.INGRESS_DIRECTION: 'physdev-out',
                          const.EGRESS_DIRECTION: 'physdev-in'}
    IPTABLES_DIRECTION_PREFIX = {const.INGRESS_DIRECTION: "i",
                                 const.EGRESS_DIRECTION: "o"}

    def __init__(self):
        super(QosLinuxbridgeAgentDriver, self).__init__()
        self.iptables_manager = None
        self.agent_api = None
        self.tbf_latency = cfg.CONF.QOS.tbf_latency

    def consume_api(self, agent_api):
        self.agent_api = agent_api

    def initialize(self):
        LOG.info("Initializing Linux bridge QoS extension")
        if self.agent_api:
            self.iptables_manager = self.agent_api.get_iptables_manager()
        if not self.iptables_manager:
            # If agent_api can't provide iptables_manager, it can be
            # created here for extension needs
            self.iptables_manager = iptables_manager.IptablesManager(
                state_less=True,
                use_ipv6=ipv6_utils.is_enabled_and_bind_by_default())
        self.iptables_manager.initialize_mangle_table()

    def _dscp_chain_name(self, direction, device):
        return iptables_manager.get_chain_name(
            "qos-%s%s" % (self.IPTABLES_DIRECTION_PREFIX[direction],
                          device[3:]))

    def _dscp_rule(self, direction, device):
        return ('-m physdev --%s %s --physdev-is-bridged '
                '-j $%s') % (self.IPTABLES_DIRECTION[direction],
                             device,
                             self._dscp_chain_name(direction, device))

    def _dscp_rule_tag(self, device):
        return "dscp-%s" % device

    @log_helpers.log_method_call
    def create_bandwidth_limit(self, port, rule):
        tc_wrapper = self._get_tc_wrapper(port)
        if rule.direction == const.INGRESS_DIRECTION:
            tc_wrapper.set_tbf_bw_limit(
                rule.max_kbps, rule.max_burst_kbps, self.tbf_latency)
        else:
            tc_wrapper.set_filters_bw_limit(
                rule.max_kbps, self._get_egress_burst_value(rule)
            )

    @log_helpers.log_method_call
    def update_bandwidth_limit(self, port, rule):
        tc_wrapper = self._get_tc_wrapper(port)
        if rule.direction == const.INGRESS_DIRECTION:
            tc_wrapper.update_tbf_bw_limit(
                rule.max_kbps, rule.max_burst_kbps, self.tbf_latency)
        else:
            tc_wrapper.update_filters_bw_limit(
                rule.max_kbps, self._get_egress_burst_value(rule)
            )

    @log_helpers.log_method_call
    def delete_bandwidth_limit(self, port):
        tc_wrapper = self._get_tc_wrapper(port)
        tc_wrapper.delete_filters_bw_limit()

    @log_helpers.log_method_call
    def delete_bandwidth_limit_ingress(self, port):
        tc_wrapper = self._get_tc_wrapper(port)
        tc_wrapper.delete_tbf_bw_limit()

    @log_helpers.log_method_call
    def create_dscp_marking(self, port, rule):
        with self.iptables_manager.defer_apply():
            self._set_outgoing_qos_chain_for_port(port)
            self._set_dscp_mark_rule(port, rule.dscp_mark)

    @log_helpers.log_method_call
    def update_dscp_marking(self, port, rule):
        with self.iptables_manager.defer_apply():
            self._delete_dscp_mark_rule(port)
            self._set_outgoing_qos_chain_for_port(port)
            self._set_dscp_mark_rule(port, rule.dscp_mark)

    @log_helpers.log_method_call
    def delete_dscp_marking(self, port):
        with self.iptables_manager.defer_apply():
            self._delete_dscp_mark_rule(port)
            self._delete_outgoing_qos_chain_for_port(port)

    def _set_outgoing_qos_chain_for_port(self, port):
        chain_name = self._dscp_chain_name(
            const.EGRESS_DIRECTION, port['device'])
        chain_rule = self._dscp_rule(
            const.EGRESS_DIRECTION, port['device'])
        self.iptables_manager.ipv4['mangle'].add_chain(chain_name)
        self.iptables_manager.ipv6['mangle'].add_chain(chain_name)

        self.iptables_manager.ipv4['mangle'].add_rule('POSTROUTING',
                                                      chain_rule)
        self.iptables_manager.ipv6['mangle'].add_rule('POSTROUTING',
                                                      chain_rule)

    def _delete_outgoing_qos_chain_for_port(self, port):
        chain_name = self._dscp_chain_name(
            const.EGRESS_DIRECTION, port['device'])
        chain_rule = self._dscp_rule(
            const.EGRESS_DIRECTION, port['device'])
        if self._qos_chain_is_empty(port, 4):
            self.iptables_manager.ipv4['mangle'].remove_chain(chain_name)
            self.iptables_manager.ipv4['mangle'].remove_rule('POSTROUTING',
                                                             chain_rule)
        if self._qos_chain_is_empty(port, 6):
            self.iptables_manager.ipv6['mangle'].remove_chain(chain_name)
            self.iptables_manager.ipv6['mangle'].remove_rule('POSTROUTING',
                                                             chain_rule)

    def _set_dscp_mark_rule(self, port, dscp_value):
        chain_name = self._dscp_chain_name(
            const.EGRESS_DIRECTION, port['device'])
        # iptables rules use hexadecimal values with --set-dscp
        rule = "-j DSCP --set-dscp %s" % format(dscp_value, '#04x')
        self.iptables_manager.ipv4['mangle'].add_rule(
            chain_name, rule, tag=self._dscp_rule_tag(port['device']))
        self.iptables_manager.ipv6['mangle'].add_rule(
            chain_name, rule, tag=self._dscp_rule_tag(port['device']))

    def _delete_dscp_mark_rule(self, port):
        self.iptables_manager.ipv4['mangle'].clear_rules_by_tag(
            self._dscp_rule_tag(port['device']))
        self.iptables_manager.ipv6['mangle'].clear_rules_by_tag(
            self._dscp_rule_tag(port['device']))

    def _qos_chain_is_empty(self, port, ip_version=4):
        chain_name = self._dscp_chain_name(
            const.EGRESS_DIRECTION, port['device'])
        rules_in_chain = self.iptables_manager.get_chain(
            "mangle", chain_name, ip_version=ip_version)
        return len(rules_in_chain) == 0

    def _get_tc_wrapper(self, port):
        return tc_lib.TcCommand(
            port['device'],
            cfg.CONF.QOS.kernel_hz,
        )
