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

import re
import signal

from neutron_lib.plugins.ml2 import ovs_constants
from oslo_log import log as logging

from neutron.agent.common import async_process
from neutron.agent.linux import iptables_manager
from neutron.common import utils as common_utils
from neutron.plugins.ml2.common import constants as comm_consts

LOG = logging.getLogger(__name__)


class TcpdumpException(Exception):
    pass


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


def extract_dscp_value_from_iptables_rules(rules):
    pattern = (r"^-A neutron-linuxbri-qos-.* -j DSCP "
               "--set-dscp (?P<dscp_value>0x[A-Fa-f0-9]+)$")
    for rule in rules:
        m = re.match(pattern, rule)
        if m:
            return int(m.group("dscp_value"), 16)


def wait_until_bandwidth_limit_rule_applied(check_function, port_vif, rule):
    def _bandwidth_limit_rule_applied():
        bw_rule = check_function(port_vif)
        expected = None, None
        if rule:
            expected = rule.max_kbps, rule.max_burst_kbps
        return bw_rule == expected

    common_utils.wait_until_true(_bandwidth_limit_rule_applied)


def wait_until_egress_bandwidth_limit_rule_applied(bridge, port_vif, rule):
    wait_until_bandwidth_limit_rule_applied(
        bridge.get_egress_bw_limit_for_port, port_vif, rule)


def wait_until_ingress_bandwidth_limit_rule_applied(bridge, port_vif, rule):
    wait_until_bandwidth_limit_rule_applied(
        bridge.get_ingress_bw_limit_for_port, port_vif, rule)


def wait_until_dscp_marking_rule_applied_ovs(bridge, port_vif, rule):
    def _dscp_marking_rule_applied():
        port_num = bridge.get_port_ofport(port_vif)

        flows = bridge.dump_flows_for(table='0', in_port=str(port_num))
        dscp_mark = extract_mod_nw_tos_action(flows)

        expected = None
        if rule:
            expected = rule << 2
        return dscp_mark == expected

    common_utils.wait_until_true(_dscp_marking_rule_applied)


def wait_until_pkt_meter_rule_applied_ovs(bridge, port_vif, port_id,
                                          direction, mac=None,
                                          type_=comm_consts.METER_FLAG_PPS):
    def _pkt_rate_limit_rule_applied():
        port_num = bridge.get_port_ofport(port_vif)
        port_vlan = bridge.get_port_tag_by_name(port_vif)
        key = "%s_%s_%s" % (type_, port_id, direction)
        meter_id = bridge.get_value_from_other_config(
            port_vif, key, value_type=int)

        if direction == "egress":
            flows = bridge.dump_flows_for(
                table=ovs_constants.PACKET_RATE_LIMIT, in_port=str(port_num),
                dl_src=str(mac))
        else:
            flows = bridge.dump_flows_for(
                table=ovs_constants.PACKET_RATE_LIMIT, dl_vlan=str(port_vlan),
                dl_dst=str(mac))
        if mac:
            return bool(flows) and meter_id
        else:
            return not bool(flows) and not meter_id

    common_utils.wait_until_true(_pkt_rate_limit_rule_applied)


def wait_until_dscp_marking_rule_applied_linuxbridge(namespace, port_vif,
                                                     expected_rule):

    iptables = iptables_manager.IptablesManager(
        namespace=namespace)

    def _dscp_marking_rule_applied():
        mangle_rules = iptables.get_rules_for_table("mangle")
        dscp_mark = extract_dscp_value_from_iptables_rules(mangle_rules)
        return dscp_mark == expected_rule

    common_utils.wait_until_true(_dscp_marking_rule_applied)


def wait_for_dscp_marked_packet(sender_vm, receiver_vm, dscp_mark):
    cmd = [
        "tcpdump", "-i", receiver_vm.port.name, "-nlt",
        "src", sender_vm.ip, 'and', 'dst', receiver_vm.ip]
    if dscp_mark:
        cmd += ["and", "(ip[1] & 0xfc == %s)" % (dscp_mark << 2)]
    tcpdump_async = async_process.AsyncProcess(cmd, run_as_root=True,
                                               namespace=receiver_vm.namespace)
    tcpdump_async.start(block=True)

    sender_vm.block_until_ping(receiver_vm.ip)

    try:
        tcpdump_async.stop(kill_signal=signal.SIGINT)
    except async_process.AsyncProcessException:
        # If it was already stopped than we don't care about it
        pass

    tcpdump_stderr_lines = []
    pattern = r"(?P<packets_count>^\d+) packets received by filter"
    for line in tcpdump_async.iter_stderr():
        m = re.match(pattern, line)
        if m and int(m.group("packets_count")) != 0:
            return
        tcpdump_stderr_lines.append(line)

    tcpdump_stdout_lines = [line for line in tcpdump_async.iter_stdout()]
    LOG.debug("Captured output lines from tcpdump. Stdout: %s; Stderr: %s",
              tcpdump_stdout_lines, tcpdump_stderr_lines)

    raise TcpdumpException(
        "No packets marked with DSCP = %(dscp_mark)s received from %(src)s "
        "to %(dst)s" % {'dscp_mark': dscp_mark,
                        'src': sender_vm.ip,
                        'dst': receiver_vm.ip})


def extract_vlan_id(flows):
    if flows:
        flow_list = flows.splitlines()
        for flow in flow_list:
            if 'mod_vlan_vid' in flow:
                actions = flow.partition('actions=')[2]
                after_mod = actions.partition('mod_vlan_vid:')[2]
                return int(after_mod.partition(',')[0])


def wait_for_mod_vlan_id_applied(bridge, expected_vlan_id):
    def _vlan_id_rule_applied():
        flows = bridge.dump_flows_for(table='0')
        vlan_id = extract_vlan_id(flows)
        return vlan_id == expected_vlan_id

    common_utils.wait_until_true(_vlan_id_rule_applied)
