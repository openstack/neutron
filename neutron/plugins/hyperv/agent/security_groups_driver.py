#Copyright 2014 Cloudbase Solutions SRL
#All Rights Reserved.
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
# @author: Claudiu Belu, Cloudbase Solutions Srl

from neutron.agent import firewall
from neutron.openstack.common import log as logging
from neutron.plugins.hyperv.agent import utilsfactory
from neutron.plugins.hyperv.agent import utilsv2

LOG = logging.getLogger(__name__)


class HyperVSecurityGroupsDriver(firewall.FirewallDriver):
    """Security Groups Driver.

    Security Groups implementation for Hyper-V VMs.
    """

    _ACL_PROP_MAP = {
        'direction': {'ingress': utilsv2.HyperVUtilsV2._ACL_DIR_IN,
                      'egress': utilsv2.HyperVUtilsV2._ACL_DIR_OUT},
        'ethertype': {'IPv4': utilsv2.HyperVUtilsV2._ACL_TYPE_IPV4,
                      'IPv6': utilsv2.HyperVUtilsV2._ACL_TYPE_IPV6},
        'protocol': {'icmp': utilsv2.HyperVUtilsV2._ICMP_PROTOCOL},
        'default': "ANY",
        'address_default': {'IPv4': '0.0.0.0/0', 'IPv6': '::/0'}
    }

    def __init__(self):
        self._utils = utilsfactory.get_hypervutils()
        self._security_ports = {}

    def prepare_port_filter(self, port):
        LOG.debug('Creating port %s rules' % len(port['security_group_rules']))

        # newly created port, add default rules.
        if port['device'] not in self._security_ports:
            LOG.debug('Creating default reject rules.')
            self._utils.create_default_reject_all_rules(port['id'])

        self._security_ports[port['device']] = port
        self._create_port_rules(port['id'], port['security_group_rules'])

    def _create_port_rules(self, port_id, rules):
        for rule in rules:
            param_map = self._create_param_map(rule)
            try:
                self._utils.create_security_rule(port_id, **param_map)
            except Exception as ex:
                LOG.error(_('Hyper-V Exception: %(hyperv_exeption)s while '
                            'adding rule: %(rule)s'),
                          dict(hyperv_exeption=ex, rule=rule))

    def _remove_port_rules(self, port_id, rules):
        for rule in rules:
            param_map = self._create_param_map(rule)
            try:
                self._utils.remove_security_rule(port_id, **param_map)
            except Exception as ex:
                LOG.error(_('Hyper-V Exception: %(hyperv_exeption)s while '
                            'removing rule: %(rule)s'),
                          dict(hyperv_exeption=ex, rule=rule))

    def _create_param_map(self, rule):
        if 'port_range_min' in rule and 'port_range_max' in rule:
            local_port = '%s-%s' % (rule['port_range_min'],
                                    rule['port_range_max'])
        else:
            local_port = self._ACL_PROP_MAP['default']

        return {
            'direction': self._ACL_PROP_MAP['direction'][rule['direction']],
            'acl_type': self._ACL_PROP_MAP['ethertype'][rule['ethertype']],
            'local_port': local_port,
            'protocol': self._get_rule_protocol(rule),
            'remote_address': self._get_rule_remote_address(rule)
        }

    def apply_port_filter(self, port):
        LOG.info('Aplying port filter.')

    def update_port_filter(self, port):
        LOG.info('Updating port rules.')

        if port['device'] not in self._security_ports:
            self.prepare_port_filter(port)
            return

        old_port = self._security_ports[port['device']]
        rules = old_port['security_group_rules']
        param_port_rules = port['security_group_rules']

        new_rules = [r for r in param_port_rules if r not in rules]
        remove_rules = [r for r in rules if r not in param_port_rules]

        LOG.info("Creating %s new rules, removing %s old rules." % (
                 len(new_rules), len(remove_rules)))

        self._remove_port_rules(old_port['id'], remove_rules)
        self._create_port_rules(port['id'], new_rules)

        self._security_ports[port['device']] = port

    def remove_port_filter(self, port):
        LOG.info('Removing port filter')
        self._security_ports.pop(port['device'], None)

    @property
    def ports(self):
        return self._security_ports

    def _get_rule_remote_address(self, rule):
        if rule['direction'] is 'ingress':
            ip_prefix = 'source_ip_prefix'
        else:
            ip_prefix = 'dest_ip_prefix'

        if ip_prefix in rule:
            return rule[ip_prefix]
        return self._ACL_PROP_MAP['address_default'][rule['ethertype']]

    def _get_rule_protocol(self, rule):
        protocol = self._get_rule_prop_or_default(rule, 'protocol')
        if protocol in self._ACL_PROP_MAP['protocol'].keys():
            return self._ACL_PROP_MAP['protocol'][protocol]

        return protocol

    def _get_rule_prop_or_default(self, rule, prop):
        if prop in rule:
            return rule[prop]
        return self._ACL_PROP_MAP['default']
