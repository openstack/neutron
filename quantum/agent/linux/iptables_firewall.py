# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012, Nachi Ueno, NTT MCL, Inc.
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

from quantum.agent import firewall
from quantum.common import constants
from quantum.openstack.common import log as logging


LOG = logging.getLogger(__name__)
SG_CHAIN = 'sg-chain'
INGRESS_DIRECTION = 'ingress'
EGRESS_DIRECTION = 'egress'
CHAIN_NAME_PREFIX = {INGRESS_DIRECTION: 'i',
                     EGRESS_DIRECTION: 'o'}
IPTABLES_DIRECTION = {INGRESS_DIRECTION: 'physdev-out',
                      EGRESS_DIRECTION: 'physdev-in'}


class IptablesFirewallDriver(firewall.FirewallDriver):
    """Driver which enforces security groups through iptables rules."""

    def __init__(self, iptables_manager):
        self.iptables = iptables_manager

        # list of port which has security group
        self.filtered_ports = {}
        self._add_fallback_chain_v4v6()

    @property
    def ports(self):
        return self.filtered_ports

    def prepare_port_filter(self, port):
        LOG.debug(_("Preparing device (%s) filter"), port['device'])
        self._remove_chains()
        self.filtered_ports[port['device']] = port
        # each security group has it own chains
        self._setup_chains()
        self.iptables.apply()

    def update_port_filter(self, port):
        LOG.debug(_("Updating device (%s) filter"), port['device'])
        if not port['device'] in self.filtered_ports:
            LOG.info(_('Attempted to update port filter which is not '
                     'filtered %s') % port['device'])
            return
        self._remove_chains()
        self.filtered_ports[port['device']] = port
        self._setup_chains()
        self.iptables.apply()

    def remove_port_filter(self, port):
        LOG.debug(_("Removing device (%s) filter"), port['device'])
        if not self.filtered_ports.get(port['device']):
            LOG.info(_('Attempted to remove port filter which is not '
                     'filtered %r'), port)
            return
        self._remove_chains()
        self.filtered_ports.pop(port['device'], None)
        self._setup_chains()
        self.iptables.apply()

    def _setup_chains(self):
        """Setup ingress and egress chain for a port. """
        self._add_chain_by_name_v4v6(SG_CHAIN)
        for port in self.filtered_ports.values():
            self._setup_chain(port, INGRESS_DIRECTION)
            self._setup_chain(port, EGRESS_DIRECTION)
            self.iptables.ipv4['filter'].add_rule(SG_CHAIN, '-j ACCEPT')
            self.iptables.ipv6['filter'].add_rule(SG_CHAIN, '-j ACCEPT')

    def _remove_chains(self):
        """Remove ingress and egress chain for a port"""
        for port in self.filtered_ports.values():
            self._remove_chain(port, INGRESS_DIRECTION)
            self._remove_chain(port, EGRESS_DIRECTION)
        self._remove_chain_by_name_v4v6(SG_CHAIN)

    def _setup_chain(self, port, DIRECTION):
        self._add_chain(port, DIRECTION)
        self._add_rule_by_security_group(port, DIRECTION)

    def _remove_chain(self, port, DIRECTION):
        chain_name = self._port_chain_name(port, DIRECTION)
        self._remove_chain_by_name_v4v6(chain_name)

    def _add_fallback_chain_v4v6(self):
        self.iptables.ipv4['filter'].add_chain('sg-fallback')
        self.iptables.ipv4['filter'].add_rule('sg-fallback', '-j DROP')
        self.iptables.ipv6['filter'].add_chain('sg-fallback')
        self.iptables.ipv6['filter'].add_rule('sg-fallback', '-j DROP')

    def _add_chain_by_name_v4v6(self, chain_name):
        self.iptables.ipv6['filter'].add_chain(chain_name)
        self.iptables.ipv4['filter'].add_chain(chain_name)

    def _remove_chain_by_name_v4v6(self, chain_name):
        self.iptables.ipv4['filter'].ensure_remove_chain(chain_name)
        self.iptables.ipv6['filter'].ensure_remove_chain(chain_name)

    def _add_rule_to_chain_v4v6(self, chain_name, ipv4_rules, ipv6_rules):
        for rule in ipv4_rules:
            self.iptables.ipv4['filter'].add_rule(chain_name, rule)

        for rule in ipv6_rules:
            self.iptables.ipv6['filter'].add_rule(chain_name, rule)

    def _add_chain(self, port, direction):
        chain_name = self._port_chain_name(port, direction)
        self._add_chain_by_name_v4v6(chain_name)

        # Note(nati) jump to the security group chain (SG_CHAIN)
        # This is needed because the packet may much two rule in port
        # if the two port is in the same host
        # We accept the packet at the end of SG_CHAIN.

        # jump to the security group chain
        device = port['device']
        jump_rule = ['-m physdev --physdev-is-bridged --%s '
                     '%s -j $%s' % (IPTABLES_DIRECTION[direction],
                                    device,
                                    SG_CHAIN)]
        self._add_rule_to_chain_v4v6('FORWARD', jump_rule, jump_rule)

        # jump to the chain based on the device
        jump_rule = ['-m physdev --physdev-is-bridged --%s '
                     '%s -j $%s' % (IPTABLES_DIRECTION[direction],
                                    device,
                                    chain_name)]
        self._add_rule_to_chain_v4v6(SG_CHAIN, jump_rule, jump_rule)

        if direction == EGRESS_DIRECTION:
            self._add_rule_to_chain_v4v6('INPUT', jump_rule, jump_rule)

    def _split_sgr_by_ethertype(self, security_group_rules):
        ipv4_sg_rules = []
        ipv6_sg_rules = []
        for rule in security_group_rules:
            if rule.get('ethertype') == constants.IPv4:
                ipv4_sg_rules.append(rule)
            elif rule.get('ethertype') == constants.IPv6:
                if rule.get('protocol') == 'icmp':
                    rule['protocol'] = 'icmpv6'
                ipv6_sg_rules.append(rule)
        return ipv4_sg_rules, ipv6_sg_rules

    def _select_sgr_by_direction(self, port, direction):
        return [rule
                for rule in port.get('security_group_rules', [])
                if rule['direction'] == direction]

    def _arp_spoofing_rule(self, port):
        return ['-m mac ! --mac-source %s -j DROP' % port['mac_address']]

    def _ip_spoofing_rule(self, port, ipv4_rules, ipv6_rules):
        #Note(nati) allow dhcp or RA packet
        ipv4_rules += ['-p udp --sport 68 --dport 67 -j RETURN']
        ipv6_rules += ['-p icmpv6 -j RETURN']
        for ip in port['fixed_ips']:
            if netaddr.IPAddress(ip).version == 4:
                ipv4_rules += ['! -s %s -j DROP' % ip]
            else:
                ipv6_rules += ['! -s %s -j DROP' % ip]

    def _drop_dhcp_rule(self):
        #Note(nati) Drop dhcp packet from VM
        return ['-p udp --sport 67 --dport 68 -j DROP']

    def _add_rule_by_security_group(self, port, direction):
        chain_name = self._port_chain_name(port, direction)
        # select rules for current direction
        security_group_rules = self._select_sgr_by_direction(port, direction)
        # split groups by ip version
        # for ipv4, iptables command is used
        # for ipv6, iptables6 command is used
        ipv4_sg_rules, ipv6_sg_rules = self._split_sgr_by_ethertype(
            security_group_rules)
        ipv4_iptables_rule = []
        ipv6_iptables_rule = []
        if direction == EGRESS_DIRECTION:
            ipv4_iptables_rule += self._arp_spoofing_rule(port)
            ipv6_iptables_rule += self._arp_spoofing_rule(port)
            self._ip_spoofing_rule(port,
                                   ipv4_iptables_rule,
                                   ipv6_iptables_rule)
            ipv4_iptables_rule += self._drop_dhcp_rule()
        ipv4_iptables_rule += self._convert_sgr_to_iptables_rules(
            ipv4_sg_rules)
        ipv6_iptables_rule += self._convert_sgr_to_iptables_rules(
            ipv6_sg_rules)
        self._add_rule_to_chain_v4v6(chain_name,
                                     ipv4_iptables_rule,
                                     ipv6_iptables_rule)

    def _convert_sgr_to_iptables_rules(self, security_group_rules):
        iptables_rules = []
        self._drop_invalid_packets(iptables_rules)
        self._allow_established(iptables_rules)
        for rule in security_group_rules:
            args = ['-j RETURN']
            args += self._protocol_arg(rule.get('protocol'))
            args += self._port_arg('dport',
                                   rule.get('protocol'),
                                   rule.get('port_range_min'),
                                   rule.get('port_range_max'))
            args += self._port_arg('sport',
                                   rule.get('protocol'),
                                   rule.get('source_port_range_min'),
                                   rule.get('source_port_range_max'))
            args += self._ip_prefix_arg('s',
                                        rule.get('source_ip_prefix'))
            args += self._ip_prefix_arg('d',
                                        rule.get('dest_ip_prefix'))
            iptables_rules += [' '.join(args)]

        iptables_rules += ['-j $sg-fallback']

        return iptables_rules

    def _drop_invalid_packets(self, iptables_rules):
        # Always drop invalid packets
        iptables_rules += ['-m state --state ' 'INVALID -j DROP']
        return iptables_rules

    def _allow_established(self, iptables_rules):
        # Allow established connections
        iptables_rules += ['-m state --state ESTABLISHED,RELATED -j RETURN']
        return iptables_rules

    def _protocol_arg(self, protocol):
        if protocol:
            return ['-p', protocol]
        return []

    def _port_arg(self, direction, protocol, port_range_min, port_range_max):
        if not (protocol in ['udp', 'tcp'] and port_range_min):
            return []

        if port_range_min == port_range_max:
            return ['--%s' % direction, '%s' % (port_range_min,)]
        else:
            return ['-m', 'multiport',
                    '--%ss' % direction,
                    '%s:%s' % (port_range_min, port_range_max)]

    def _ip_prefix_arg(self, direction, ip_prefix):
        #NOTE (nati) : source_group_id is converted to list of source_
        # ip_prefix in server side
        if ip_prefix:
            return ['-%s' % direction, ip_prefix]
        return []

    def _port_chain_name(self, port, direction):
        #Note (nati) make chain name short less than 28 char
        # with extra prefix
        # ( see comment in iptables_manager )
        return '%s%s' % (CHAIN_NAME_PREFIX[direction],
                         port['device'][3:13])

    def filter_defer_apply_on(self):
        self.iptables.defer_apply_on()

    def filter_defer_apply_off(self):
        self.iptables.defer_apply_off()
