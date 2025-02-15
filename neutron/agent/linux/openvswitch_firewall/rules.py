# Copyright 2015 Red Hat, Inc.
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

import collections

import netaddr
from neutron_lib.agent.common import constants as agent_consts
from neutron_lib import constants as n_consts
from neutron_lib.plugins.ml2 import ovs_constants as ovs_consts

from neutron._i18n import _
from neutron.agent.linux.openvswitch_firewall import constants as ovsfw_consts
from neutron.common import utils

CT_STATES = [
    ovsfw_consts.OF_STATE_ESTABLISHED_NOT_REPLY,
    ovsfw_consts.OF_STATE_NEW_NOT_ESTABLISHED]

FLOW_FIELD_FOR_IPVER_AND_DIRECTION = {
    (n_consts.IP_VERSION_4, n_consts.EGRESS_DIRECTION): 'nw_dst',
    (n_consts.IP_VERSION_6, n_consts.EGRESS_DIRECTION): 'ipv6_dst',
    (n_consts.IP_VERSION_4, n_consts.INGRESS_DIRECTION): 'nw_src',
    (n_consts.IP_VERSION_6, n_consts.INGRESS_DIRECTION): 'ipv6_src',
}

FORBIDDEN_PREFIXES = (n_consts.IPv4_ANY, n_consts.IPv6_ANY)


def is_valid_prefix(ip_prefix):
    # IPv6 have multiple ways how to describe ::/0 network, converting to
    # IPNetwork and back to string unifies it
    return (ip_prefix and
            str(netaddr.IPNetwork(ip_prefix)) not in FORBIDDEN_PREFIXES)


def _assert_mergeable_rules(rule_conj_list):
    """Assert a given (rule, conj_ids) list has mergeable rules.

    The given rules must be the same except for port_range_{min,max}
    differences.
    """
    rule_tmpl = rule_conj_list[0][0].copy()
    rule_tmpl.pop('port_range_min', None)
    rule_tmpl.pop('port_range_max', None)
    for rule, conj_id in rule_conj_list[1:]:
        rule1 = rule.copy()
        rule1.pop('port_range_min', None)
        rule1.pop('port_range_max', None)
        if rule_tmpl != rule1:
            raise RuntimeError(
                _("Incompatible SG rules detected: %(rule1)s and %(rule2)s. "
                  "They cannot be merged. This should not happen.") %
                {'rule1': rule_tmpl, 'rule2': rule})


def merge_common_rules(rule_conj_list):
    """Take a list of (rule, conj_id) and merge elements with the same rules.
    Return a list of (rule, conj_id_list).
    """
    if len(rule_conj_list) == 1:
        rule, conj_id = rule_conj_list[0]
        return [(rule, [conj_id])]

    _assert_mergeable_rules(rule_conj_list)
    rule_conj_map = collections.defaultdict(list)
    for rule, conj_id in rule_conj_list:
        rule_conj_map[(rule.get('port_range_min'),
                       rule.get('port_range_max'))].append(conj_id)

    result = []
    rule_tmpl = rule_conj_list[0][0]
    rule_tmpl.pop('port_range_min', None)
    rule_tmpl.pop('port_range_max', None)
    for (port_min, port_max), conj_ids in rule_conj_map.items():
        rule = rule_tmpl.copy()
        if port_min is not None:
            rule['port_range_min'] = port_min
        if port_max is not None:
            rule['port_range_max'] = port_max
        result.append((rule, conj_ids))
    return result


def _merge_port_ranges_helper(port_range_item):
    # Sort with 'port' but 'min' things must come first.
    port, m, dummy = port_range_item
    return port * 2 + (0 if m == 'min' else 1)


def merge_port_ranges(rule_conj_list):
    """Take a list of (rule, conj_id) and transform into a list
    whose rules don't overlap. Return a list of (rule, conj_id_list).
    """
    if len(rule_conj_list) == 1:
        rule, conj_id = rule_conj_list[0]
        return [(rule, [conj_id])]

    _assert_mergeable_rules(rule_conj_list)
    port_ranges = []
    for rule, conj_id in rule_conj_list:
        port_ranges.append((rule.get('port_range_min', 1), 'min', conj_id))
        port_ranges.append((rule.get('port_range_max', 65535), 'max', conj_id))

    port_ranges.sort(key=_merge_port_ranges_helper)

    # The idea here is to scan the port_ranges list in an ascending order,
    # keeping active conjunction IDs and range in cur_conj and cur_range_min.
    # A 'min' port_ranges item means an addition to cur_conj, while a 'max'
    # item means a removal.
    result = []
    rule_tmpl = rule_conj_list[0][0]
    cur_conj = {}
    cur_range_min = None
    for port, m, conj_id in port_ranges:
        if m == 'min':
            if conj_id in cur_conj:
                cur_conj[conj_id] += 1
                continue
            if cur_conj and cur_range_min != port:
                rule = rule_tmpl.copy()
                rule['port_range_min'] = cur_range_min
                rule['port_range_max'] = port - 1
                result.append((rule, list(cur_conj.keys())))
            cur_range_min = port
            cur_conj[conj_id] = 1
        else:
            if cur_conj[conj_id] > 1:
                cur_conj[conj_id] -= 1
                continue
            if cur_range_min <= port:
                rule = rule_tmpl.copy()
                rule['port_range_min'] = cur_range_min
                rule['port_range_max'] = port
                result.append((rule, list(cur_conj.keys())))
                # The next port range without 'port' starts from (port + 1)
                cur_range_min = port + 1
            del cur_conj[conj_id]

    if (len(result) == 1 and result[0][0]['port_range_min'] == 1 and
            result[0][0]['port_range_max'] == 65535):
        del result[0][0]['port_range_min']
        del result[0][0]['port_range_max']
    return result


def flow_priority_offset(rule, conjunction=False):
    """Calculate flow priority offset from rule.
    Whether the rule belongs to conjunction flows or not is decided
    upon existence of rule['remote_group_id'] or
    rule['remote_address_group_id'] but can be overridden
    to be True using the optional conjunction arg.
    """
    conj_offset = 0 if 'remote_group_id' in rule or \
                       'remote_address_group_id' in rule or \
                       conjunction else 4
    protocol = rule.get('protocol')
    if protocol is None:
        return conj_offset

    if protocol in [n_consts.PROTO_NUM_ICMP, n_consts.PROTO_NUM_IPV6_ICMP]:
        if 'port_range_min' not in rule:
            return conj_offset + 1
        if 'port_range_max' not in rule:
            return conj_offset + 2
    return conj_offset + 3


def create_flows_from_rule_and_port(rule, port, conjunction=False):
    """Create flows from given args.
    For description of the optional conjunction arg, see flow_priority_offset.
    """
    ethertype = rule['ethertype']
    direction = rule['direction']
    dst_ip_prefix = rule.get('dest_ip_prefix')
    src_ip_prefix = rule.get('source_ip_prefix')

    flow_template = {
        'priority': 70 + flow_priority_offset(rule, conjunction),
        'dl_type': ovsfw_consts.ethertype_to_dl_type_map[ethertype],
        agent_consts.PORT_REG_NAME: port.ofport,
    }

    if is_valid_prefix(dst_ip_prefix):
        flow_template[FLOW_FIELD_FOR_IPVER_AND_DIRECTION[(
            utils.get_ip_version(dst_ip_prefix), n_consts.EGRESS_DIRECTION)]
                     ] = dst_ip_prefix

    if is_valid_prefix(src_ip_prefix):
        flow_template[FLOW_FIELD_FOR_IPVER_AND_DIRECTION[(
            utils.get_ip_version(src_ip_prefix), n_consts.INGRESS_DIRECTION)]
                     ] = src_ip_prefix

    flows = create_protocol_flows(direction, flow_template, port, rule)

    return flows


def populate_flow_common(direction, flow_template, port):
    """Initialize common flow fields."""
    if direction == n_consts.INGRESS_DIRECTION:
        flow_template['table'] = ovs_consts.RULES_INGRESS_TABLE
        flow_template['actions'] = f"output:{port.ofport:d}"
    elif direction == n_consts.EGRESS_DIRECTION:
        flow_template['table'] = ovs_consts.RULES_EGRESS_TABLE
        # Traffic can be both ingress and egress, check that no ingress rules
        # should be applied
        flow_template['actions'] = 'resubmit(,{:d})'.format(
            ovs_consts.ACCEPT_OR_INGRESS_TABLE)
    return flow_template


def create_protocol_flows(direction, flow_template, port, rule):
    flow_template = populate_flow_common(direction,
                                         flow_template.copy(),
                                         port)
    protocol = rule.get('protocol')
    if protocol is not None:
        flow_template['nw_proto'] = protocol

    if protocol in [n_consts.PROTO_NUM_ICMP, n_consts.PROTO_NUM_IPV6_ICMP]:
        flows = create_icmp_flows(flow_template, rule)
    else:
        flows = create_port_range_flows(flow_template, rule)
    return flows or [flow_template]


def create_port_range_flows(flow_template, rule):
    protocol = ovsfw_consts.REVERSE_IP_PROTOCOL_MAP_WITH_PORTS.get(
        rule.get('protocol'))
    if protocol is None:
        return []
    flows = []
    src_port_match = f'{protocol:s}_src'
    src_port_min = rule.get('source_port_range_min')
    src_port_max = rule.get('source_port_range_max')
    dst_port_match = f'{protocol:s}_dst'
    dst_port_min = rule.get('port_range_min')
    dst_port_max = rule.get('port_range_max')

    dst_port_range = []
    if dst_port_min and dst_port_max:
        dst_port_range = utils.port_rule_masking(dst_port_min, dst_port_max)

    src_port_range = []
    if src_port_min and src_port_max:
        src_port_range = utils.port_rule_masking(src_port_min, src_port_max)
        for port in src_port_range:
            flow = flow_template.copy()
            flow[src_port_match] = port
            if dst_port_range:
                for port in dst_port_range:
                    dst_flow = flow.copy()
                    dst_flow[dst_port_match] = port
                    flows.append(dst_flow)
            else:
                flows.append(flow)
    else:
        for port in dst_port_range:
            flow = flow_template.copy()
            flow[dst_port_match] = port
            flows.append(flow)

    return flows


def create_icmp_flows(flow_template, rule):
    icmp_type = rule.get('port_range_min')
    if icmp_type is None:
        return
    flow = flow_template.copy()
    flow['icmp_type'] = icmp_type

    icmp_code = rule.get('port_range_max')
    if icmp_code is not None:
        flow['icmp_code'] = icmp_code
    return [flow]


def _flow_priority_offset_from_conj_id(conj_id):
    """Return a flow priority offset encoded in a conj_id."""
    # A base conj_id, which is returned by ConjIdMap.get_conj_id, is a
    # multiple of 8, and we use 2 conj_ids per offset.
    return conj_id % 8 // 2


def create_flows_for_ip_address_and_mac(ip_address, mac_address, direction,
                                        ethertype, vlan_tag, conj_ids):
    """Create flows from a rule, ip, and mac addresses derived from
    remote_group_id or remote_address_group_id.
    """
    net = netaddr.IPNetwork(str(ip_address))
    any_src_ip = net.prefixlen == 0

    # Group conj_ids per priority.
    conj_id_lists = [[] for i in range(4)]
    for conj_id in conj_ids:
        conj_id_lists[
            _flow_priority_offset_from_conj_id(conj_id)].append(conj_id)

    ip_prefix = str(netaddr.IPNetwork(ip_address).cidr)

    flow_template = {
        'dl_type': ovsfw_consts.ethertype_to_dl_type_map[ethertype],
        agent_consts.NET_REG_NAME: vlan_tag,  # needed for project separation
    }

    ip_ver = utils.get_ip_version(ip_prefix)

    if direction == n_consts.EGRESS_DIRECTION:
        flow_template['table'] = ovs_consts.RULES_EGRESS_TABLE
    elif direction == n_consts.INGRESS_DIRECTION:
        flow_template['table'] = ovs_consts.RULES_INGRESS_TABLE

    flow_template[FLOW_FIELD_FOR_IPVER_AND_DIRECTION[(
        ip_ver, direction)]] = ip_prefix

    if any_src_ip and mac_address:
        # A remote address group can contain an any_src_ip without
        # mac_address and in that case we don't set the dl_src.
        flow_template['dl_src'] = mac_address

    result = []
    for offset, conj_id_list in enumerate(conj_id_lists):
        if not conj_id_list:
            continue
        flow_template['priority'] = 70 + offset
        result.extend(
            substitute_conjunction_actions([flow_template], 1, conj_id_list))
    return result


def create_accept_flows(flow):
    flow['ct_state'] = CT_STATES[0]
    result = [flow.copy()]
    flow['ct_state'] = CT_STATES[1]
    if flow['table'] == ovs_consts.RULES_INGRESS_TABLE:
        flow['actions'] = (
            'ct(commit,zone=NXM_NX_REG{:d}[0..15]),{:s},'
            'resubmit(,{:d})'.format(
                agent_consts.REG_NET, flow['actions'],
                ovs_consts.ACCEPTED_INGRESS_TRAFFIC_TABLE)
        )
    result.append(flow)
    return result


def substitute_conjunction_actions(flows, dimension, conj_ids):
    result = []
    for flow in flows:
        for i in range(2):
            new_flow = flow.copy()
            new_flow['ct_state'] = CT_STATES[i]
            new_flow['actions'] = ','.join(
                ["conjunction(%d,%d/2)" % (s + i, dimension)
                 for s in conj_ids])
            result.append(new_flow)

    return result


def create_conj_flows(port, conj_id, direction, ethertype):
    """Generate "accept" flows for a given conjunction ID."""
    flow_template = {
        'priority': 70 + _flow_priority_offset_from_conj_id(conj_id),
        'conj_id': conj_id,
        'dl_type': ovsfw_consts.ethertype_to_dl_type_map[ethertype],
        # This reg_port matching is for delete_all_port_flows.
        # The matching is redundant as it has been done by
        # conjunction(...,2/2) flows and flows can be summarized
        # without this.
        agent_consts.PORT_REG_NAME: port.ofport,
    }
    flow_template = populate_flow_common(direction, flow_template, port)
    flows = create_accept_flows(flow_template)
    flows[1]['conj_id'] += 1
    return flows
