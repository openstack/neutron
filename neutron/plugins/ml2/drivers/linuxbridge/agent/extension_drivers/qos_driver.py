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

import collections

from oslo_log import helpers as log_helpers
from oslo_log import log

from neutron._i18n import _LI
from neutron.agent.l2.extensions import qos_linux as qos
from neutron.agent.linux import iptables_manager
from neutron.agent.linux import tc_lib
import neutron.common.constants as const
from neutron.services.qos.drivers.linuxbridge import driver
from neutron.services.qos import qos_consts

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
        self._port_rules = collections.defaultdict(dict)

    def initialize(self):
        LOG.info(_LI("Initializing Linux bridge QoS extension"))
        self.iptables_manager = iptables_manager.IptablesManager(use_ipv6=True)

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
        self.update_bandwidth_limit(port, rule)

    @log_helpers.log_method_call
    def update_bandwidth_limit(self, port, rule):
        device = port.get('device')
        port_id = port.get('port_id')
        if not device:
            LOG.debug("update_bandwidth_limit was received for port %s but "
                      "device was not found. It seems that port is already "
                      "deleted", port_id)
            return

        self._port_rules[port_id][qos_consts.RULE_TYPE_BANDWIDTH_LIMIT] = rule
        max, burst, min = self._get_port_bw_parameters(port_id)
        tc_wrapper = tc_lib.TcCommand(device)
        tc_wrapper.set_bw(max, burst, min, const.EGRESS_DIRECTION)

    @log_helpers.log_method_call
    def delete_bandwidth_limit(self, port):
        device = port.get('device')
        port_id = port.get('port_id')
        if not device:
            LOG.debug("delete_bandwidth_limit was received for port %s but "
                      "device was not found. It seems that port is already "
                      "deleted", port_id)
            return

        self._port_rules[port_id].pop(qos_consts.RULE_TYPE_BANDWIDTH_LIMIT,
                                      None)
        max, burst, min = self._get_port_bw_parameters(port_id)
        tc_wrapper = tc_lib.TcCommand(device)
        if not min:
            tc_wrapper.delete_bw(const.EGRESS_DIRECTION)
        else:
            tc_wrapper.set_bw(max, burst, min, const.EGRESS_DIRECTION)

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
        rule = "-j DSCP --set-dscp %s" % dscp_value
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

    @log_helpers.log_method_call
    def create_minimum_bandwidth(self, port, rule):
        self.update_minimum_bandwidth(port, rule)

    @log_helpers.log_method_call
    def update_minimum_bandwidth(self, port, rule):
        device = port.get('device')
        port_id = port.get('port_id')
        if not device:
            LOG.debug("update_minimum_bandwidth was received for port %s but "
                      "device was not found. It seems that port is already "
                      "deleted", port_id)
            return

        self._port_rules[port_id][
            qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH] = rule
        max, burst, min = self._get_port_bw_parameters(port_id)
        tc_wrapper = tc_lib.TcCommand(device)
        tc_wrapper.set_bw(max, burst, min, const.EGRESS_DIRECTION)

    @log_helpers.log_method_call
    def delete_minimum_bandwidth(self, port):
        device = port.get('device')
        port_id = port.get('port_id')
        if not device:
            LOG.debug("delete_minimum_bandwidth was received for port %s but "
                      "device was not found. It seems that port is already "
                      "deleted", port_id)
            return

        self._port_rules[port_id].pop(qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH,
                                      None)
        max, burst, min = self._get_port_bw_parameters(port_id)
        tc_wrapper = tc_lib.TcCommand(device)
        if not max and not burst:
            tc_wrapper.delete_bw(const.EGRESS_DIRECTION)
        else:
            tc_wrapper.set_bw(max, burst, min, const.EGRESS_DIRECTION)

    def _get_port_bw_parameters(self, port_id):
        rules = self._port_rules[port_id]
        if not rules:
            return None, None, None
        rule_min = rules.get(qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH)
        rule_limit = rules.get(qos_consts.RULE_TYPE_BANDWIDTH_LIMIT)
        min = rule_min.min_kbps if rule_min else None
        max = rule_limit.max_kbps if rule_limit else None
        burst = (self._get_egress_burst_value(rule_limit) if rule_limit else
                 None)
        return max, burst, min
