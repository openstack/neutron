# Copyright 2013 VMware, Inc.
# All Rights Reserved
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

from neutron.openstack.common import log
from neutron.plugins.vmware.common import nsx_utils

LOG = log.getLogger(__name__)
# Protocol number look up for supported protocols
protocol_num_look_up = {'tcp': 6, 'icmp': 1, 'udp': 17}


def _convert_to_nsx_rule(session, cluster, rule, with_id=False):
    """Converts a Neutron security group rule to the NSX format.

    This routine also replaces Neutron IDs with NSX UUIDs.
    """
    nsx_rule = {}
    params = ['remote_ip_prefix', 'protocol',
              'remote_group_id', 'port_range_min',
              'port_range_max', 'ethertype']
    if with_id:
        params.append('id')

    for param in params:
        value = rule.get(param)
        if param not in rule:
            nsx_rule[param] = value
        elif not value:
            pass
        elif param == 'remote_ip_prefix':
            nsx_rule['ip_prefix'] = rule['remote_ip_prefix']
        elif param == 'remote_group_id':
            nsx_rule['profile_uuid'] = nsx_utils.get_nsx_security_group_id(
                session, cluster, rule['remote_group_id'])

        elif param == 'protocol':
            try:
                nsx_rule['protocol'] = int(rule['protocol'])
            except (ValueError, TypeError):
                nsx_rule['protocol'] = (
                    protocol_num_look_up[rule['protocol']])
        else:
            nsx_rule[param] = value
    return nsx_rule


def _convert_to_nsx_rules(session, cluster, rules, with_id=False):
    """Converts a list of Neutron security group rules to the NSX format."""
    nsx_rules = {'logical_port_ingress_rules': [],
                 'logical_port_egress_rules': []}
    for direction in ['logical_port_ingress_rules',
                      'logical_port_egress_rules']:
        for rule in rules[direction]:
            nsx_rules[direction].append(
                _convert_to_nsx_rule(session, cluster, rule, with_id))
    return nsx_rules


def get_security_group_rules_nsx_format(session, cluster,
                                        security_group_rules, with_id=False):
    """Convert neutron security group rules into NSX format.

    This routine splits Neutron security group rules into two lists, one
    for ingress rules and the other for egress rules.
    """

    def fields(rule):
        _fields = ['remote_ip_prefix', 'remote_group_id', 'protocol',
                   'port_range_min', 'port_range_max', 'protocol', 'ethertype']
        if with_id:
            _fields.append('id')
        return dict((k, v) for k, v in rule.iteritems() if k in _fields)

    ingress_rules = []
    egress_rules = []
    for rule in security_group_rules:
        if rule.get('souce_group_id'):
            rule['remote_group_id'] = nsx_utils.get_nsx_security_group_id(
                session, cluster, rule['remote_group_id'])

        if rule['direction'] == 'ingress':
            ingress_rules.append(fields(rule))
        elif rule['direction'] == 'egress':
            egress_rules.append(fields(rule))
    rules = {'logical_port_ingress_rules': egress_rules,
             'logical_port_egress_rules': ingress_rules}
    return _convert_to_nsx_rules(session, cluster, rules, with_id)


def merge_security_group_rules_with_current(session, cluster,
                                            new_rules, current_rules):
    merged_rules = get_security_group_rules_nsx_format(
        session, cluster, current_rules)
    for new_rule in new_rules:
        rule = new_rule['security_group_rule']
        if rule['direction'] == 'ingress':
            merged_rules['logical_port_egress_rules'].append(
                _convert_to_nsx_rule(session, cluster, rule))
        elif rule['direction'] == 'egress':
            merged_rules['logical_port_ingress_rules'].append(
                _convert_to_nsx_rule(session, cluster, rule))
    return merged_rules


def remove_security_group_with_id_and_id_field(rules, rule_id):
    """Remove rule by rule_id.

    This function receives all of the current rule associated with a
    security group and then removes the rule that matches the rule_id. In
    addition it removes the id field in the dict with each rule since that
    should not be passed to nsx.
    """
    for rule_direction in rules.values():
        item_to_remove = None
        for port_rule in rule_direction:
            if port_rule['id'] == rule_id:
                item_to_remove = port_rule
            else:
                # remove key from dictionary for NSX
                del port_rule['id']
        if item_to_remove:
            rule_direction.remove(item_to_remove)
