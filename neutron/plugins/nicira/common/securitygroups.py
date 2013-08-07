# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Nicira, Inc.
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
#
# @author: Aaron Rosen, Nicira Networks, Inc.

from neutron.extensions import securitygroup as ext_sg

# Protocol number look up for supported protocols
protocol_num_look_up = {'tcp': 6, 'icmp': 1, 'udp': 17}


class NVPSecurityGroups(object):

    def _convert_to_nvp_rule(self, rule, with_id=False):
        """Converts Neutron API security group rule to NVP API."""
        nvp_rule = {}
        params = ['remote_ip_prefix', 'protocol',
                  'remote_group_id', 'port_range_min',
                  'port_range_max', 'ethertype']
        if with_id:
            params.append('id')

        for param in params:
            value = rule.get(param)
            if param not in rule:
                nvp_rule[param] = value
            elif not value:
                pass
            elif param == 'remote_ip_prefix':
                nvp_rule['ip_prefix'] = rule['remote_ip_prefix']
            elif param == 'remote_group_id':
                nvp_rule['profile_uuid'] = rule['remote_group_id']
            elif param == 'protocol':
                try:
                    nvp_rule['protocol'] = int(rule['protocol'])
                except (ValueError, TypeError):
                    nvp_rule['protocol'] = (
                        protocol_num_look_up[rule['protocol']])
            else:
                nvp_rule[param] = value
        return nvp_rule

    def _convert_to_nvp_rules(self, rules, with_id=False):
        """Converts a list of Neutron API security group rules to NVP API."""
        nvp_rules = {'logical_port_ingress_rules': [],
                     'logical_port_egress_rules': []}
        for direction in ['logical_port_ingress_rules',
                          'logical_port_egress_rules']:
            for rule in rules[direction]:
                nvp_rules[direction].append(
                    self._convert_to_nvp_rule(rule, with_id))
        return nvp_rules

    def _get_security_group_rules_nvp_format(self, context, security_group_id,
                                             with_id=False):
        """Query neutron db for security group rules."""
        fields = ['remote_ip_prefix', 'remote_group_id', 'protocol',
                  'port_range_min', 'port_range_max', 'protocol', 'ethertype']
        if with_id:
            fields.append('id')

        filters = {'security_group_id': [security_group_id],
                   'direction': ['ingress']}
        ingress_rules = self.get_security_group_rules(context, filters, fields)
        filters = {'security_group_id': [security_group_id],
                   'direction': ['egress']}
        egress_rules = self.get_security_group_rules(context, filters, fields)
        rules = {'logical_port_ingress_rules': egress_rules,
                 'logical_port_egress_rules': ingress_rules}
        return self._convert_to_nvp_rules(rules, with_id)

    def _get_profile_uuid(self, context, remote_group_id):
        """Return profile id from novas group id."""
        security_group = self.get_security_group(context, remote_group_id)
        if not security_group:
            raise ext_sg.SecurityGroupNotFound(id=remote_group_id)
        return security_group['id']

    def _merge_security_group_rules_with_current(self, context, new_rules,
                                                 security_group_id):
        merged_rules = self._get_security_group_rules_nvp_format(
            context, security_group_id)
        for new_rule in new_rules:
            rule = new_rule['security_group_rule']
            rule['security_group_id'] = security_group_id
            if rule.get('souce_group_id'):
                rule['remote_group_id'] = self._get_profile_uuid(
                    context, rule['remote_group_id'])
            if rule['direction'] == 'ingress':
                merged_rules['logical_port_egress_rules'].append(
                    self._convert_to_nvp_rule(rule))
            elif rule['direction'] == 'egress':
                merged_rules['logical_port_ingress_rules'].append(
                    self._convert_to_nvp_rule(rule))
        return merged_rules

    def _remove_security_group_with_id_and_id_field(self, rules, rule_id):
        """Remove rule by rule_id.

        This function receives all of the current rule associated with a
        security group and then removes the rule that matches the rule_id. In
        addition it removes the id field in the dict with each rule since that
        should not be passed to nvp.
        """
        for rule_direction in rules.values():
            item_to_remove = None
            for port_rule in rule_direction:
                if port_rule['id'] == rule_id:
                    item_to_remove = port_rule
                else:
                    # remove key from dictionary for NVP
                    del port_rule['id']
            if item_to_remove:
                rule_direction.remove(item_to_remove)
