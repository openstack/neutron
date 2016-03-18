# Copyright (c) 2015 Red Hat, Inc.
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

from neutron.agent.linux import utils as agent_utils


def extract_mod_nw_tos_action(flows):
    tos_mark = None
    if flows:
        flow_list = flows.splitlines()
        for flow in flow_list:
            if 'mod_nw_tos' in flow:
                actions = flow.partition('actions=')[2]
                after_mod = actions.partition('mod_nw_tos:')[2]
                tos_mark = int(after_mod.partition(',')[0])
    return tos_mark


def wait_until_bandwidth_limit_rule_applied(bridge, port_vif, rule):
    def _bandwidth_limit_rule_applied():
        bw_rule = bridge.get_egress_bw_limit_for_port(port_vif)
        expected = None, None
        if rule:
            expected = rule.max_kbps, rule.max_burst_kbps
        return bw_rule == expected

    agent_utils.wait_until_true(_bandwidth_limit_rule_applied)


def wait_until_dscp_marking_rule_applied(bridge, port_vif, rule):
    def _dscp_marking_rule_applied():
        port_num = bridge.get_port_ofport(port_vif)

        flows = bridge.dump_flows_for(table='0', in_port=str(port_num))
        dscp_mark = extract_mod_nw_tos_action(flows)

        expected = None
        if rule:
            expected = rule
        return dscp_mark == expected

    agent_utils.wait_until_true(_dscp_marking_rule_applied)
