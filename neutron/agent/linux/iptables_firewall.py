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
from oslo.config import cfg

from neutron.agent import firewall
from neutron.agent.linux import iptables_manager
from neutron.common import constants
from neutron.common import ipv6_utils
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)
SG_CHAIN = 'sg-chain'
INGRESS_DIRECTION = 'ingress'
EGRESS_DIRECTION = 'egress'
SPOOF_FILTER = 'spoof-filter'
CHAIN_NAME_PREFIX = {INGRESS_DIRECTION: 'i',
                     EGRESS_DIRECTION: 'o',
                     SPOOF_FILTER: 's'}
LINUX_DEV_LEN = 14


class IptablesFirewallDriver(firewall.FirewallDriver):
    """Driver which enforces security groups through iptables rules."""
    IPTABLES_DIRECTION = {INGRESS_DIRECTION: 'physdev-out',
                          EGRESS_DIRECTION: 'physdev-in'}

    def __init__(self):
        self.iptables = iptables_manager.IptablesManager(
            root_helper=cfg.CONF.AGENT.root_helper,
            use_ipv6=ipv6_utils.is_enabled())
        # list of port which has security group
        self.filtered_ports = {}
        self._add_fallback_chain_v4v6()
        self._defer_apply = False
        self._pre_defer_filtered_ports = None

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
        if port['device'] not in self.filtered_ports:
            LOG.info(_('Attempted to update port filter which is not '
                       'filtered %s'), port['device'])
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
        """Setup ingress and egress chain for a port."""
        if not self._defer_apply:
            self._setup_chains_apply(self.filtered_ports)

    def _setup_chains_apply(self, ports):
        self._add_chain_by_name_v4v6(SG_CHAIN)
        for port in ports.values():
            self._setup_chain(port, INGRESS_DIRECTION)
            self._setup_chain(port, EGRESS_DIRECTION)
            self.iptables.ipv4['filter'].add_rule(SG_CHAIN, '-j ACCEPT')
            self.iptables.ipv6['filter'].add_rule(SG_CHAIN, '-j ACCEPT')

    def _remove_chains(self):
        """Remove ingress and egress chain for a port."""
        if not self._defer_apply:
            self._remove_chains_apply(self.filtered_ports)

    def _remove_chains_apply(self, ports):
        for port in ports.values():
            self._remove_chain(port, INGRESS_DIRECTION)
            self._remove_chain(port, EGRESS_DIRECTION)
            self._remove_chain(port, SPOOF_FILTER)
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

    def _get_device_name(self, port):
        return port['device']

    def _add_chain(self, port, direction):
        chain_name = self._port_chain_name(port, direction)
        self._add_chain_by_name_v4v6(chain_name)

        # Note(nati) jump to the security group chain (SG_CHAIN)
        # This is needed because the packet may much two rule in port
        # if the two port is in the same host
        # We accept the packet at the end of SG_CHAIN.

        # jump to the security group chain
        device = self._get_device_name(port)
        jump_rule = ['-m physdev --%s %s --physdev-is-bridged '
                     '-j $%s' % (self.IPTABLES_DIRECTION[direction],
                                 device,
                                 SG_CHAIN)]
        self._add_rule_to_chain_v4v6('FORWARD', jump_rule, jump_rule)

        # jump to the chain based on the device
        jump_rule = ['-m physdev --%s %s --physdev-is-bridged '
                     '-j $%s' % (self.IPTABLES_DIRECTION[direction],
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

    def _setup_spoof_filter_chain(self, port, table, mac_ip_pairs, rules):
        if mac_ip_pairs:
            chain_name = self._port_chain_name(port, SPOOF_FILTER)
            table.add_chain(chain_name)
            for mac, ip in mac_ip_pairs:
                if ip is None:
                    # If fixed_ips is [] this rule will be added to the end
                    # of the list after the allowed_address_pair rules.
                    table.add_rule(chain_name,
                                   '-m mac --mac-source %s -j RETURN'
                                   % mac)
                else:
                    table.add_rule(chain_name,
                                   '-m mac --mac-source %s -s %s -j RETURN'
                                   % (mac, ip))
            table.add_rule(chain_name, '-j DROP')
            rules.append('-j $%s' % chain_name)

    def _build_ipv4v6_mac_ip_list(self, mac, ip_address, mac_ipv4_pairs,
                                  mac_ipv6_pairs):
        if netaddr.IPNetwork(ip_address).version == 4:
            mac_ipv4_pairs.append((mac, ip_address))
        else:
            mac_ipv6_pairs.append((mac, ip_address))

    def _spoofing_rule(self, port, ipv4_rules, ipv6_rules):
        #Note(nati) allow dhcp or RA packet
        ipv4_rules += ['-p udp -m udp --sport 68 --dport 67 -j RETURN']
        ipv6_rules += ['-p icmpv6 -j RETURN']
        mac_ipv4_pairs = []
        mac_ipv6_pairs = []

        if isinstance(port.get('allowed_address_pairs'), list):
            for address_pair in port['allowed_address_pairs']:
                self._build_ipv4v6_mac_ip_list(address_pair['mac_address'],
                                               address_pair['ip_address'],
                                               mac_ipv4_pairs,
                                               mac_ipv6_pairs)

        for ip in port['fixed_ips']:
            self._build_ipv4v6_mac_ip_list(port['mac_address'], ip,
                                           mac_ipv4_pairs, mac_ipv6_pairs)
        if not port['fixed_ips']:
            mac_ipv4_pairs.append((port['mac_address'], None))
            mac_ipv6_pairs.append((port['mac_address'], None))

        self._setup_spoof_filter_chain(port, self.iptables.ipv4['filter'],
                                       mac_ipv4_pairs, ipv4_rules)
        self._setup_spoof_filter_chain(port, self.iptables.ipv6['filter'],
                                       mac_ipv6_pairs, ipv6_rules)

    def _drop_dhcp_rule(self):
        #Note(nati) Drop dhcp packet from VM
        return ['-p udp -m udp --sport 67 --dport 68 -j DROP']

    def _accept_inbound_icmpv6(self):
        # Allow router advertisements, multicast listener
        # and neighbor advertisement into the instance
        icmpv6_rules = []
        for icmp6_type in constants.ICMPV6_ALLOWED_TYPES:
            icmpv6_rules += ['-p icmpv6 --icmpv6-type %s -j RETURN' %
                             icmp6_type]
        return icmpv6_rules

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
            self._spoofing_rule(port,
                                ipv4_iptables_rule,
                                ipv6_iptables_rule)
            ipv4_iptables_rule += self._drop_dhcp_rule()
        if direction == INGRESS_DIRECTION:
            ipv6_iptables_rule += self._accept_inbound_icmpv6()
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
            # These arguments MUST be in the format iptables-save will
            # display them: source/dest, protocol, sport, dport, target
            # Otherwise the iptables_manager code won't be able to find
            # them to preserve their [packet:byte] counts.
            args = self._ip_prefix_arg('s',
                                       rule.get('source_ip_prefix'))
            args += self._ip_prefix_arg('d',
                                        rule.get('dest_ip_prefix'))
            args += self._protocol_arg(rule.get('protocol'))
            args += self._port_arg('sport',
                                   rule.get('protocol'),
                                   rule.get('source_port_range_min'),
                                   rule.get('source_port_range_max'))
            args += self._port_arg('dport',
                                   rule.get('protocol'),
                                   rule.get('port_range_min'),
                                   rule.get('port_range_max'))
            args += ['-j RETURN']
            iptables_rules += [' '.join(args)]

        iptables_rules += ['-j $sg-fallback']

        return iptables_rules

    def _drop_invalid_packets(self, iptables_rules):
        # Always drop invalid packets
        iptables_rules += ['-m state --state ' 'INVALID -j DROP']
        return iptables_rules

    def _allow_established(self, iptables_rules):
        # Allow established connections
        iptables_rules += ['-m state --state RELATED,ESTABLISHED -j RETURN']
        return iptables_rules

    def _protocol_arg(self, protocol):
        if not protocol:
            return []

        iptables_rule = ['-p', protocol]
        # iptables always adds '-m protocol' for udp and tcp
        if protocol in ['udp', 'tcp']:
            iptables_rule += ['-m', protocol]
        return iptables_rule

    def _port_arg(self, direction, protocol, port_range_min, port_range_max):
        if (protocol not in ['udp', 'tcp', 'icmp', 'icmpv6']
            or not port_range_min):
            return []

        if protocol in ['icmp', 'icmpv6']:
            # Note(xuhanp): port_range_min/port_range_max represent
            # icmp type/code when protocal is icmp or icmpv6
            # icmp code can be 0 so we cannot use "if port_range_max" here
            if port_range_max is not None:
                return ['--%s-type' % protocol,
                        '%s/%s' % (port_range_min, port_range_max)]
            return ['--%s-type' % protocol, '%s' % port_range_min]
        elif port_range_min == port_range_max:
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
        return iptables_manager.get_chain_name(
            '%s%s' % (CHAIN_NAME_PREFIX[direction], port['device'][3:]))

    def filter_defer_apply_on(self):
        if not self._defer_apply:
            self.iptables.defer_apply_on()
            self._pre_defer_filtered_ports = dict(self.filtered_ports)
            self._defer_apply = True

    def filter_defer_apply_off(self):
        if self._defer_apply:
            self._defer_apply = False
            self._remove_chains_apply(self._pre_defer_filtered_ports)
            self._pre_defer_filtered_ports = None
            self._setup_chains_apply(self.filtered_ports)
            self.iptables.defer_apply_off()


class OVSHybridIptablesFirewallDriver(IptablesFirewallDriver):
    OVS_HYBRID_TAP_PREFIX = 'tap'

    def _port_chain_name(self, port, direction):
        return iptables_manager.get_chain_name(
            '%s%s' % (CHAIN_NAME_PREFIX[direction], port['device']))

    def _get_device_name(self, port):
        return (self.OVS_HYBRID_TAP_PREFIX + port['device'])[:LINUX_DEV_LEN]
