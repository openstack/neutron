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

from neutronclient.common import exceptions
from neutronclient.v2_0 import client

from neutron.agent import firewall
from neutron.agent.linux import ebtables_manager
from neutron.agent.linux import iptables_manager
from neutron.common import constants
from neutron.common import ipv6_utils
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)
SG_CHAIN = 'sg-chain'
INGRESS_DIRECTION = 'ingress'
EGRESS_DIRECTION = 'egress'
CHAIN_NAME_PREFIX = {INGRESS_DIRECTION: 'i',
                     EGRESS_DIRECTION: 'o'}
SPOOFING_CHAIN_NAME_PREFIX_ARP = '-arp-'
SPOOFING_CHAIN_NAME_PREFIX_IP = '-ip-'
LINUX_DEV_LEN = 14

anti_spoof_opts = [
    cfg.BoolOpt('disable_anti_spoofing',
                default=False,
                help=_('Disable anti-spoofing for Neutron services ports')),
    cfg.StrOpt('sec_group_svc_VM_name',
               help=_("Security group service VM name")),
]

CONF = cfg.CONF
CONF.register_opts(anti_spoof_opts)


class NWFilterFirewall(object):
    """
    This class implements a network filtering mechanism by using
    ebtables.

    All port get a base filter applied. This filter provides some basic
    security such as protection against MAC spoofing, IP spoofing, and ARP
    spoofing.
    """

    def __init__(self):
        self.ebtables = ebtables_manager.EbtablesManager(
            root_helper=cfg.CONF.AGENT.root_helper,
            prefix_chain='neutron-nwfilter')
        with ebtables_manager.EbtablesManagerTransaction(self.ebtables):
            del self.ebtables.tables['nat']
            del self.ebtables.tables['broute']
            table = self.ebtables.tables['filter']
            self.fallback_chain_name = self._add_fallback_chain(table)

    def setup_basic_filtering(self, port_id, device, mac_ip_pairs):
        if port_id is None or device is None:
            return
        if mac_ip_pairs is None or mac_ip_pairs[0] is None:
            return

        table = self.ebtables.tables['filter']

        # Set rules and chains for the device
        self._setup_device_chains(table, port_id, device)

        # Set anti ARP spoofing
        arp_rules = self._setup_arp_antispoofing(mac_ip_pairs)
        arp_rules += ['-j $%s' % self.fallback_chain_name]
        arp_chain_name = self._port_chain_name(SPOOFING_CHAIN_NAME_PREFIX_ARP
                                               + port_id, INGRESS_DIRECTION)
        self._set_chain_and_rules(table, arp_chain_name, arp_rules)
        rules = ['-p arp -j $%s' % arp_chain_name]
        self._set_rules_for_device(table, port_id, rules,
                                   INGRESS_DIRECTION)

        # Set the MAC/IP anti spoofing rules and allow DHCP traffic
        # NOTE(ethuleau): more?
        # - IPv6 neighbor discovery reflection filter
        # - IPv6 RA advertisement filter
        # - ...
        # Should we implement _accept_inbound_icmpv6 (line 374) method here?
        ip_rules = self._allow_dhcp_request()
        ip_rules += self._drop_dhcp_offer_rule()
        ip_rules += self._setup_mac_ip_antispoofing(mac_ip_pairs)
        ip_rules += ['-j $%s' % self.fallback_chain_name]
        ip_chain_name = self._port_chain_name(SPOOFING_CHAIN_NAME_PREFIX_IP
                                              + port_id, INGRESS_DIRECTION)
        self._set_chain_and_rules(table, ip_chain_name, ip_rules)
        jump_rules = ['-p IPv4 -j $%s' % ip_chain_name]
        jump_rules += ['-p IPv6 -j $%s' % ip_chain_name]
        self._set_rules_for_device(table, port_id, jump_rules,
                                   INGRESS_DIRECTION)

        self.ebtables.apply()

    def unfilter_instance(self, port_id):
        if port_id is None:
            return

        table = self.ebtables.tables['filter']

        chain_name = self._port_chain_name(port_id, INGRESS_DIRECTION)
        table.ensure_remove_chain(chain_name)

        arp_chain_name = self._port_chain_name(SPOOFING_CHAIN_NAME_PREFIX_ARP +
                                               port_id,
                                               INGRESS_DIRECTION)
        table.ensure_remove_chain(arp_chain_name)

        ip_chain_name = self._port_chain_name(SPOOFING_CHAIN_NAME_PREFIX_IP +
                                              port_id,
                                              INGRESS_DIRECTION)
        table.ensure_remove_chain(ip_chain_name)

        self.ebtables.apply()

    def defer_apply_on(self):
        self.ebtables.defer_apply_on()

    def defer_apply_off(self):
        self.ebtables.defer_apply_off()

    def _setup_device_chains(self, table, port_id, device):
        # Add chain and jump to all incoming from the device
        chain_name = self._port_chain_name(port_id, INGRESS_DIRECTION)
        table.add_chain(chain_name)
        rule = '--in-interface %s -j $%s' % (device, chain_name)
        table.add_rule('FORWARD', rule, top=True)

        # NOTE(ethuleau): Do we need to apply some filters on traffic going to
        # the device (eg. DHCP request of neighbors)?

    def _allow_dhcp_request(self):
        # Note(ethuleau): The sg mixin already set default provider sg to
        # protect DHCP traffic (neutron/db/securitygroups_rpc_base.py, line
        # 254).
        # Only incoming DHCP server traffic is authorize from DHCP
        # servers IP and DHCP server traffic is drop if it's coming from the
        # VM. Should we support that in the NWFilterFirewall class?
        rules = []
        for proto in ['udp', 'tcp']:
            # NOTE(ethuleau): we limit DHCP request to not overload DHCP agents
            # One request per second with a burst of 5 (default value) is
            # enough?
            rules += ['-p IPv4 --ip-proto %s --ip-sport 68 --ip-dport 67 '
                      '--limit 1/s -j ACCEPT' % proto]
        return rules

    def _drop_dhcp_offer_rule(self):
        rules = []
        for proto in ['udp', 'tcp']:
            rules += ['-p IPv4 --ip-proto %s --ip-sport 67 --ip-dport 68 '
                      '-j DROP' % proto]
        return rules

    def _setup_mac_ip_antispoofing(self, mac_ip_pairs):
        rules = []
        for mac, ip in mac_ip_pairs:
            if ip is None:
                rules += ['-p %s -j RETURN' % mac]
            else:
                rules += ['-s %s -p %s --ip-source %s -j RETURN' %
                          (mac, self._get_ip_protocol(ip), ip)]
        return rules

    def _setup_arp_antispoofing(self, mac_ip_pairs):
        rules = []
        for mac, ip in mac_ip_pairs:
            if ip is not None:
                rules += [('-p arp --arp-opcode 2 --arp-mac-src %s '
                           '--arp-ip-src %s -j RETURN') % (mac, ip)]
        rules += ['-p ARP --arp-op Request -j ACCEPT']
        return rules

    def _add_fallback_chain(self, table):
        table.add_chain('spoofing-fallback')
        table.add_rule('spoofing-fallback', '-j DROP')
        return self.ebtables.get_chain_name('spoofing-fallback')

    def _port_chain_name(self, port_id, direction):
        return self.ebtables.get_chain_name(
            '%s%s' % (CHAIN_NAME_PREFIX[direction], port_id))

    def _get_ip_protocol(self, ip_address):
        if netaddr.IPNetwork(ip_address).version == 4:
            return 'IPv4'
        else:
            return 'IPv6'

    def _set_rules_for_device(self, table, port_id, rules, DIRECTION):
        chain_name = self._port_chain_name(port_id, DIRECTION)
        for rule in rules:
            table.add_rule(chain_name, rule)

    def _set_chain_and_rules(self, table, chain_name, rules):
        table.add_chain(chain_name)
        for rule in rules:
            table.add_rule(chain_name, rule)


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
        self.nwfilter = NWFilterFirewall()

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
            self.nwfilter.unfilter_instance(port['id'])
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

    def _get_mac_ip_pair(self, port):
        # Note(ethuleau): Why? Insted, we should drop RA from a VM port.
        #ipv6_rules += ['-p icmpv6 -j RETURN']
        mac_ip_pairs = []

        if isinstance(port.get('allowed_address_pairs'), list):
            for address_pair in port['allowed_address_pairs']:
                mac_ip_pairs.append((address_pair['mac_address'],
                                     address_pair['ip_address']))

        for ip in port['fixed_ips']:
            mac_ip_pairs.append((port['mac_address'], ip))

        if not port['fixed_ips']:
            mac_ip_pairs.append((port['mac_address'], None))

        return mac_ip_pairs

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
            sg_match = False
            secgrid = ""
            if(CONF.disable_anti_spoofing):
                # Disable anti-spoofing for specified security group

                # neutronClient credentials from neutron.conf
                # authUrl example: 'http://172.19.148.164:35357/v2.0/'
                authUrl = ('%s://%s:%s/v2.0/' %
                           (CONF.keystone_authtoken.auth_protocol,
                            CONF.keystone_authtoken.auth_host,
                            CONF.keystone_authtoken.auth_port))
                neutronClient = client.Client(
                    username=CONF.keystone_authtoken.admin_user,
                    password=CONF.keystone_authtoken.admin_password,
                    tenant_name=CONF.keystone_authtoken.admin_tenant_name,
                    auth_url=authUrl)
                try:
                    # Check if the security group service VM name configured
                    # in neutron.conf matches one of this port's security group
                    # names.
                    for secgrid in port['security_groups']:
                        secgrp = neutronClient.show_security_group(secgrid)
                        if secgrp['security_group']['name'] == \
                           CONF.sec_group_svc_VM_name:
                            sg_match = True
                            break
                except exceptions.NeutronException as e:
                    LOG.error(_('Neutron Client show_security_group call'
                              ' error: %s for sec group id %s') %
                              (str(e), str(secgrid)))

                # If port's sec gp isn't config in neutron.conf, add rule.
                if (not sg_match):
                    self._spoofing_rule(port,
                                        ipv4_iptables_rule,
                                        ipv6_iptables_rule)
                    ipv4_iptables_rule += self._drop_dhcp_rule()

            # For egress direction, anti spoofing is disabled. Add rule.
            else:
                self.nwfilter.setup_basic_filtering( \
                                        port['id'],
                                        self._get_device_name(port),
                                        self._get_mac_ip_pair(port))
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
            self.nwfilter.defer_apply_on()
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
