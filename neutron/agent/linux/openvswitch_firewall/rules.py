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

import netaddr
from neutron_lib import constants as n_consts
from oslo_log import log as logging

from neutron.agent import firewall
from neutron.agent.linux.openvswitch_firewall import constants as ovsfw_consts
from neutron.common import utils
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants \
        as ovs_consts

LOG = logging.getLogger(__name__)

CT_STATES = [
    ovsfw_consts.OF_STATE_ESTABLISHED_NOT_REPLY,
    ovsfw_consts.OF_STATE_NEW_NOT_ESTABLISHED]

FLOW_FIELD_FOR_IPVER_AND_DIRECTION = {
    (n_consts.IP_VERSION_4, firewall.EGRESS_DIRECTION): 'nw_dst',
    (n_consts.IP_VERSION_6, firewall.EGRESS_DIRECTION): 'ipv6_dst',
    (n_consts.IP_VERSION_4, firewall.INGRESS_DIRECTION): 'nw_src',
    (n_consts.IP_VERSION_6, firewall.INGRESS_DIRECTION): 'ipv6_src',
}

FORBIDDEN_PREFIXES = (n_consts.IPv4_ANY, n_consts.IPv6_ANY)


def is_valid_prefix(ip_prefix):
    # IPv6 have multiple ways how to describe ::/0 network, converting to
    # IPNetwork and back to string unifies it
    return (ip_prefix and
            str(netaddr.IPNetwork(ip_prefix)) not in FORBIDDEN_PREFIXES)


def create_flows_from_rule_and_port(rule, port):
    ethertype = rule['ethertype']
    direction = rule['direction']
    dst_ip_prefix = rule.get('dest_ip_prefix')
    src_ip_prefix = rule.get('source_ip_prefix')

    flow_template = {
        'priority': 70,
        'dl_type': ovsfw_consts.ethertype_to_dl_type_map[ethertype],
        'reg_port': port.ofport,
    }

    if is_valid_prefix(dst_ip_prefix):
        flow_template[FLOW_FIELD_FOR_IPVER_AND_DIRECTION[(
            utils.get_ip_version(dst_ip_prefix), firewall.EGRESS_DIRECTION)]
        ] = dst_ip_prefix

    if is_valid_prefix(src_ip_prefix):
        flow_template[FLOW_FIELD_FOR_IPVER_AND_DIRECTION[(
            utils.get_ip_version(src_ip_prefix), firewall.INGRESS_DIRECTION)]
        ] = src_ip_prefix

    flows = create_protocol_flows(direction, flow_template, port, rule)

    return flows


def populate_flow_common(direction, flow_template, port):
    """Initialize common flow fields."""
    if direction == firewall.INGRESS_DIRECTION:
        flow_template['table'] = ovs_consts.RULES_INGRESS_TABLE
        flow_template['actions'] = "output:{:d}".format(port.ofport)
    elif direction == firewall.EGRESS_DIRECTION:
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
    src_port_match = '{:s}_src'.format(protocol)
    src_port_min = rule.get('source_port_range_min')
    src_port_max = rule.get('source_port_range_max')
    dst_port_match = '{:s}_dst'.format(protocol)
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


def create_flows_for_ip_address(ip_address, direction, ethertype,
                                vlan_tag, conj_ids):
    """Create flows from a rule and an ip_address derived from
    remote_group_id
    """

    ip_prefix = str(netaddr.IPNetwork(ip_address).cidr)

    flow_template = {
        'priority': 70,
        'dl_type': ovsfw_consts.ethertype_to_dl_type_map[ethertype],
        'reg_net': vlan_tag,  # needed for project separation
    }

    ip_ver = utils.get_ip_version(ip_prefix)

    if direction == firewall.EGRESS_DIRECTION:
        flow_template['table'] = ovs_consts.RULES_EGRESS_TABLE
    elif direction == firewall.INGRESS_DIRECTION:
        flow_template['table'] = ovs_consts.RULES_INGRESS_TABLE

    flow_template[FLOW_FIELD_FOR_IPVER_AND_DIRECTION[(
        ip_ver, direction)]] = ip_prefix

    return substitute_conjunction_actions([flow_template], 1, conj_ids)


def create_accept_flows(flow):
    flow['ct_state'] = CT_STATES[0]
    result = [flow.copy()]
    flow['ct_state'] = CT_STATES[1]
    if flow['table'] == ovs_consts.RULES_INGRESS_TABLE:
        flow['actions'] = (
            'ct(commit,zone=NXM_NX_REG{:d}[0..15]),{:s}'.format(
                ovsfw_consts.REG_NET, flow['actions']))
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
        'priority': 70,
        'conj_id': conj_id,
        'dl_type': ovsfw_consts.ethertype_to_dl_type_map[ethertype],
        # This reg_port matching is for delete_all_port_flows.
        # The matching is redundant as it has been done by
        # conjunction(...,2/2) flows and flows can be summarized
        # without this.
        'reg_port': port.ofport,
    }
    flow_template = populate_flow_common(direction, flow_template, port)
    flows = create_accept_flows(flow_template)
    flows[1]['conj_id'] += 1
    return flows
