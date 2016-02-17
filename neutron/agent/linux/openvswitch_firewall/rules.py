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
from oslo_log import log as logging
import six

from neutron.agent import firewall
from neutron.agent.linux.openvswitch_firewall import constants as ovsfw_consts
from neutron.common import constants
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants \
        as ovs_consts

LOG = logging.getLogger(__name__)


def create_flows_from_rule_and_port(rule, port):
    ethertype = rule['ethertype']
    direction = rule['direction']
    dst_ip_prefix = rule.get('dest_ip_prefix')
    src_ip_prefix = rule.get('source_ip_prefix')

    flow_template = {
        'priority': 70,
        'dl_type': ovsfw_consts.ethertype_to_dl_type_map[ethertype],
        'reg5': port.ofport,
    }

    if dst_ip_prefix and dst_ip_prefix != "0.0.0.0/0":
        flow_template["nw_dst"] = dst_ip_prefix

    if src_ip_prefix and src_ip_prefix != "0.0.0.0/0":
        flow_template["nw_src"] = src_ip_prefix

    flows = create_protocol_flows(direction, flow_template, port, rule)

    return flows


def create_protocol_flows(direction, flow_template, port, rule):
    flow_template = flow_template.copy()
    if direction == firewall.INGRESS_DIRECTION:
        flow_template['table'] = ovs_consts.RULES_INGRESS_TABLE
        flow_template['dl_dst'] = port.mac
        flow_template['actions'] = ('ct(commit,zone=NXM_NX_REG5[0..15]),'
                                    'output:{:d}'.format(port.ofport))
    elif direction == firewall.EGRESS_DIRECTION:
        flow_template['table'] = ovs_consts.RULES_EGRESS_TABLE
        flow_template['dl_src'] = port.mac
        # Traffic can be both ingress and egress, check that no ingress rules
        # should be applied
        flow_template['actions'] = 'resubmit(,{:d})'.format(
            ovs_consts.ACCEPT_OR_INGRESS_TABLE)
    protocol = rule.get('protocol')
    try:
        flow_template['nw_proto'] = ovsfw_consts.protocol_to_nw_proto[protocol]
        if rule['ethertype'] == constants.IPv6 and protocol == 'icmp':
            flow_template['nw_proto'] = constants.PROTO_NUM_IPV6_ICMP
    except KeyError:
        pass

    flows = create_port_range_flows(flow_template, rule)
    if not flows:
        return [flow_template]
    return flows


def create_port_range_flows(flow_template, rule):
    protocol = rule.get('protocol')
    if protocol not in ovsfw_consts.PROTOCOLS_WITH_PORTS:
        return []
    flows = []
    src_port_match = '{:s}_src'.format(protocol)
    #FIXME(jlibosva): Actually source_port_range_min is just a dead code in
    #                 security groups rpc layer and should be removed
    src_port_min = rule.get('source_port_range_min')
    src_port_max = rule.get('source_port_range_max')
    dst_port_match = '{:s}_dst'.format(protocol)
    dst_port_min = rule.get('port_range_min')
    dst_port_max = rule.get('port_range_max')

    if src_port_min and src_port_max:
        for port in six.moves.range(src_port_min, src_port_max + 1):
            flow = flow_template.copy()
            flow[src_port_match] = port
            try:
                for port in six.moves.range(dst_port_min, dst_port_max + 1):
                    dst_flow = flow.copy()
                    dst_flow[dst_port_match] = port
                    flows.append(dst_flow)
            except TypeError:
                flows.append(flow)
    elif dst_port_min and dst_port_max:
        for port in six.moves.range(dst_port_min, dst_port_max + 1):
            flow = flow_template.copy()
            flow[dst_port_match] = port
            flows.append(flow)

    return flows


def create_rule_for_ip_address(ip_address, rule):
    new_rule = rule.copy()
    del new_rule['remote_group_id']
    direction = rule['direction']
    ip_prefix = str(netaddr.IPNetwork(ip_address).cidr)
    new_rule[firewall.DIRECTION_IP_PREFIX[direction]] = ip_prefix
    LOG.debug('RULGEN: From rule %s with IP %s created new rule %s',
              rule, ip_address, new_rule)
    return new_rule
