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

import collections
import ctypes
from ctypes import util
import sys

import netaddr
from neutron_lib import constants
from neutron_lib.utils import helpers
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import netutils

from neutron.agent import firewall
from neutron.agent.linux import ip_conntrack
from neutron.agent.linux import ipset_manager
from neutron.agent.linux import iptables_comments as ic
from neutron.agent.linux import iptables_manager
from neutron.agent.linux import utils as a_utils
from neutron.common import _constants as const
from neutron.common import utils as c_utils


LOG = logging.getLogger(__name__)
SG_CHAIN = 'sg-chain'
SPOOF_FILTER = 'spoof-filter'
CHAIN_NAME_PREFIX = {constants.INGRESS_DIRECTION: 'i',
                     constants.EGRESS_DIRECTION: 'o',
                     SPOOF_FILTER: 's'}
IPSET_DIRECTION = {constants.INGRESS_DIRECTION: 'src',
                   constants.EGRESS_DIRECTION: 'dst'}
comment_rule = iptables_manager.comment_rule
libc = ctypes.CDLL(util.find_library('libc.so.6'))


def get_hybrid_port_name(port_name):
    return (constants.TAP_DEVICE_PREFIX + port_name)[:constants.LINUX_DEV_LEN]


class mac_iptables(netaddr.mac_eui48):
    """mac format class for netaddr to match iptables representation."""
    word_sep = ':'


class IptablesFirewallDriver(firewall.FirewallDriver):
    """Driver which enforces security groups through iptables rules."""
    IPTABLES_DIRECTION = {constants.INGRESS_DIRECTION: 'physdev-out',
                          constants.EGRESS_DIRECTION: 'physdev-in'}
    CONNTRACK_ZONE_PER_PORT = False

    def __init__(self, namespace=None):
        self.iptables = iptables_manager.IptablesManager(
            state_less=True,
            use_ipv6=netutils.is_ipv6_enabled(),
            namespace=namespace)
        # TODO(majopela, shihanzhang): refactor out ipset to a separate
        # driver composed over this one
        self.ipset = ipset_manager.IpsetManager(namespace=namespace)
        # list of port which has security group
        self.filtered_ports = {}
        self.unfiltered_ports = {}
        self.trusted_ports = []
        self.ipconntrack = ip_conntrack.get_conntrack(
            self.iptables.get_rules_for_table, self.filtered_ports,
            self.unfiltered_ports, namespace=namespace,
            zone_per_port=self.CONNTRACK_ZONE_PER_PORT)
        self._add_fallback_chain_v4v6()
        self._defer_apply = False
        self._pre_defer_filtered_ports = None
        self._pre_defer_unfiltered_ports = None
        # List of security group rules for ports residing on this host
        self.sg_rules = {}
        self.pre_sg_rules = None
        # List of security group member ips for ports residing on this host
        self.sg_members = collections.defaultdict(
            lambda: collections.defaultdict(list))
        self.pre_sg_members = None
        self.enable_ipset = cfg.CONF.SECURITYGROUP.enable_ipset
        self.updated_rule_sg_ids = set()
        self.updated_sg_members = set()
        self.devices_with_updated_sg_members = collections.defaultdict(list)
        self._iptables_protocol_name_map = {}
        self._check_netfilter_for_bridges()

    @staticmethod
    def _check_netfilter_for_bridges():
        """Check if br_netfilter is loaded and the needed flags for IPtables"""
        log_warning = False
        if not a_utils.execute(
                ['sysctl', '-N', 'net.bridge'], run_as_root=True,
                log_fail_as_error=False, check_exit_code=False,
                privsep_exec=True):
            LOG.warning('Kernel module br_netfilter is not loaded.')
            log_warning = True
        if not log_warning:
            for proto in ('arp', 'ip', 'ip6'):
                key = 'net.bridge.bridge-nf-call-%stables' % proto
                enabled = a_utils.execute(
                    ['sysctl', '-b', key], run_as_root=True,
                    log_fail_as_error=False, check_exit_code=False,
                    privsep_exec=True)
                if enabled == '1':
                    status = 'enabled'
                    log_method = LOG.debug
                else:
                    status = 'disabled'
                    log_method = LOG.warning
                    log_warning = True
                log_method('Key %(key)s is %(status)s',
                           {'key': key, 'status': status})

        if log_warning:
            LOG.warning('Please ensure that netfilter options for bridge are '
                        'enabled to provide working security groups.')

    @property
    def ports(self):
        return dict(self.filtered_ports, **self.unfiltered_ports)

    def _update_remote_security_group_members(self, sec_group_ids):
        for sg_id in sec_group_ids:
            for device in self.filtered_ports.values():
                if sg_id in device.get('security_group_source_groups', []):
                    self.devices_with_updated_sg_members[sg_id].append(device)

    def security_group_updated(self, action_type, sec_group_ids,
                               device_ids=None):
        device_ids = device_ids or []
        if action_type == 'sg_rule':
            self.updated_rule_sg_ids.update(sec_group_ids)
        elif action_type == 'sg_member':
            if device_ids:
                self.updated_sg_members.update(device_ids)
            else:
                self._update_remote_security_group_members(sec_group_ids)

    def process_trusted_ports(self, port_ids):
        """Process ports that are trusted and shouldn't be filtered."""
        for port in port_ids:
            if port not in self.trusted_ports:
                jump_rule = self._generate_trusted_port_rules(port)
                self._add_rules_to_chain_v4v6(
                    'FORWARD', jump_rule, jump_rule, comment=ic.TRUSTED_ACCEPT)
                self.trusted_ports.append(port)

    def remove_trusted_ports(self, port_ids):
        for port in port_ids:
            if port in self.trusted_ports:
                jump_rule = self._generate_trusted_port_rules(port)
                self._remove_rule_from_chain_v4v6(
                    'FORWARD', jump_rule, jump_rule)
                self.trusted_ports.remove(port)

    def _generate_trusted_port_rules(self, port):
        rt = '-m physdev --%%s %s --physdev-is-bridged -j ACCEPT' % (
            self._get_device_name(port))
        return [rt % (self.IPTABLES_DIRECTION[constants.INGRESS_DIRECTION]),
                rt % (self.IPTABLES_DIRECTION[constants.EGRESS_DIRECTION])]

    def update_security_group_rules(self, sg_id, sg_rules):
        LOG.debug("Update rules of security group (%s)", sg_id)
        self.sg_rules[sg_id] = sg_rules

    def update_security_group_members(self, sg_id, sg_members):
        LOG.debug("Update members of security group (%s)", sg_id)
        self.sg_members[sg_id] = collections.defaultdict(list, sg_members)
        if self.enable_ipset:
            self._update_ipset_members(sg_id, sg_members)

    def _update_ipset_members(self, sg_id, sg_members):
        devices = self.devices_with_updated_sg_members.pop(sg_id, None)
        for ip_version, current_ips in sg_members.items():
            add_ips, del_ips = self.ipset.set_members(
                sg_id, ip_version, current_ips)
            if devices and del_ips:
                # remove prefix from del_ips
                ips = [str(netaddr.IPNetwork(del_ip).ip) for del_ip in del_ips]
                self.ipconntrack.delete_conntrack_state_by_remote_ips(
                    devices, ip_version, ips)

    def _set_ports(self, port):
        if not firewall.port_sec_enabled(port):
            self.unfiltered_ports[port['device']] = port
            self.filtered_ports.pop(port['device'], None)
        else:
            self.filtered_ports[port['device']] = port
            self.unfiltered_ports.pop(port['device'], None)

    def _unset_ports(self, port):
        self.unfiltered_ports.pop(port['device'], None)
        self.filtered_ports.pop(port['device'], None)

    def _remove_conntrack_entries_from_port_deleted(self, port):
        device_info = self.filtered_ports.get(port['device'])
        if not device_info:
            return
        for ethertype in [constants.IPv4, constants.IPv6]:
            self.ipconntrack.delete_conntrack_state_by_remote_ips(
                [device_info], ethertype, set())

    def prepare_port_filter(self, port):
        LOG.debug("Preparing device (%s) filter", port['device'])
        self._set_ports(port)
        # each security group has it own chains
        self._setup_chains()
        return self.iptables.apply()

    def update_port_filter(self, port):
        LOG.debug("Updating device (%s) filter", port['device'])
        if port['device'] not in self.ports:
            LOG.info('Attempted to update port filter which is not '
                     'filtered %s', port['device'])
            return
        self._remove_chains()
        self._set_ports(port)
        self._setup_chains()
        return self.iptables.apply()

    def remove_port_filter(self, port):
        LOG.debug("Removing device (%s) filter", port['device'])
        if port['device'] not in self.ports:
            LOG.info('Attempted to remove port filter which is not '
                     'filtered %r', port)
            return
        self._remove_chains()
        self._remove_conntrack_entries_from_port_deleted(port)
        self._unset_ports(port)
        self._setup_chains()
        return self.iptables.apply()

    def _add_accept_rule_port_sec(self, port, direction):
        self._update_port_sec_rules(port, direction, add=True)

    def _remove_rule_port_sec(self, port, direction):
        self._update_port_sec_rules(port, direction, add=False)

    def _remove_rule_from_chain_v4v6(self, chain_name, ipv4_rules, ipv6_rules):
        for rule in ipv4_rules:
            self.iptables.ipv4['filter'].remove_rule(chain_name, rule)

        for rule in ipv6_rules:
            self.iptables.ipv6['filter'].remove_rule(chain_name, rule)

    def _setup_chains(self):
        """Setup ingress and egress chain for a port."""
        if not self._defer_apply:
            self._setup_chains_apply(self.filtered_ports,
                                     self.unfiltered_ports)

    def _setup_chains_apply(self, ports, unfiltered_ports):
        self._add_chain_by_name_v4v6(SG_CHAIN)
        # sort by port so we always do this deterministically between
        # agent restarts and don't cause unnecessary rule differences
        for pname in sorted(ports):
            port = ports[pname]
            self._add_conntrack_jump(port)
            self._setup_chain(port, constants.INGRESS_DIRECTION)
            self._setup_chain(port, constants.EGRESS_DIRECTION)
        self.iptables.ipv4['filter'].add_rule(SG_CHAIN, '-j ACCEPT')
        self.iptables.ipv6['filter'].add_rule(SG_CHAIN, '-j ACCEPT')

        for port in unfiltered_ports.values():
            self._add_accept_rule_port_sec(port, constants.INGRESS_DIRECTION)
            self._add_accept_rule_port_sec(port, constants.EGRESS_DIRECTION)

    def _remove_chains(self):
        """Remove ingress and egress chain for a port."""
        if not self._defer_apply:
            self._remove_chains_apply(self.filtered_ports,
                                      self.unfiltered_ports)

    def _remove_chains_apply(self, ports, unfiltered_ports):
        for port in ports.values():
            self._remove_chain(port, constants.INGRESS_DIRECTION)
            self._remove_chain(port, constants.EGRESS_DIRECTION)
            self._remove_chain(port, SPOOF_FILTER)
            self._remove_conntrack_jump(port)
        for port in unfiltered_ports.values():
            self._remove_rule_port_sec(port, constants.INGRESS_DIRECTION)
            self._remove_rule_port_sec(port, constants.EGRESS_DIRECTION)
        self._remove_chain_by_name_v4v6(SG_CHAIN)

    def _setup_chain(self, port, DIRECTION):
        self._add_chain(port, DIRECTION)
        self._add_rules_by_security_group(port, DIRECTION)

    def _remove_chain(self, port, DIRECTION):
        chain_name = self._port_chain_name(port, DIRECTION)
        self._remove_chain_by_name_v4v6(chain_name)

    def _add_fallback_chain_v4v6(self):
        self.iptables.ipv4['filter'].add_chain('sg-fallback')
        self.iptables.ipv4['filter'].add_rule('sg-fallback', '-j DROP',
                                              comment=ic.UNMATCH_DROP)
        self.iptables.ipv6['filter'].add_chain('sg-fallback')
        self.iptables.ipv6['filter'].add_rule('sg-fallback', '-j DROP',
                                              comment=ic.UNMATCH_DROP)

    def _add_chain_by_name_v4v6(self, chain_name):
        self.iptables.ipv4['filter'].add_chain(chain_name)
        self.iptables.ipv6['filter'].add_chain(chain_name)

    def _remove_chain_by_name_v4v6(self, chain_name):
        self.iptables.ipv4['filter'].remove_chain(chain_name)
        self.iptables.ipv6['filter'].remove_chain(chain_name)

    def _add_rules_to_chain_v4v6(self, chain_name, ipv4_rules, ipv6_rules,
                                 top=False, comment=None):
        for rule in ipv4_rules:
            self.iptables.ipv4['filter'].add_rule(chain_name, rule,
                                                  top=top, comment=comment)

        for rule in ipv6_rules:
            self.iptables.ipv6['filter'].add_rule(chain_name, rule,
                                                  top=top, comment=comment)

    def _get_device_name(self, port):
        if not isinstance(port, dict):
            return port
        return port['device']

    def _update_port_sec_rules(self, port, direction, add=False):
        # add/remove rules in FORWARD and INPUT chain
        device = self._get_device_name(port)

        jump_rule = ['-m physdev --%s %s --physdev-is-bridged '
                     '-j ACCEPT' % (self.IPTABLES_DIRECTION[direction],
                                    device)]
        if add:
            self._add_rules_to_chain_v4v6(
                'FORWARD', jump_rule, jump_rule, comment=ic.PORT_SEC_ACCEPT)
        else:
            self._remove_rule_from_chain_v4v6('FORWARD', jump_rule, jump_rule)

        if direction == constants.EGRESS_DIRECTION:
            if add:
                self._add_rules_to_chain_v4v6('INPUT', jump_rule, jump_rule,
                                              comment=ic.PORT_SEC_ACCEPT)
            else:
                self._remove_rule_from_chain_v4v6(
                    'INPUT', jump_rule, jump_rule)

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
        # Security group chain has to be applied before unfiltered
        # or trusted ports
        self._add_rules_to_chain_v4v6('FORWARD', jump_rule, jump_rule,
                                      top=True, comment=ic.VM_INT_SG)

        # jump to the chain based on the device
        jump_rule = ['-m physdev --%s %s --physdev-is-bridged '
                     '-j $%s' % (self.IPTABLES_DIRECTION[direction],
                                 device,
                                 chain_name)]
        self._add_rules_to_chain_v4v6(SG_CHAIN, jump_rule, jump_rule,
                                      comment=ic.SG_TO_VM_SG)

        if direction == constants.EGRESS_DIRECTION:
            self._add_rules_to_chain_v4v6('INPUT', jump_rule, jump_rule,
                                          comment=ic.INPUT_TO_SG)

    def _get_br_device_name(self, port):
        return ('brq' + port['network_id'])[:constants.LINUX_DEV_LEN]

    def _get_port_device_name(self, port):
        if port['device'].startswith(constants.TAP_DEVICE_PREFIX):
            return port['device'][4:]
        return port['device']

    def _get_jump_rules(self, port, create=True):
        zone = self.ipconntrack.get_device_zone(port, create=create)
        if not zone:
            return []
        br_dev = self._get_br_device_name(port)
        port_dev = self._get_device_name(port)
        # match by interface for bridge input
        match_interface = '-i %s'
        match_physdev = '-m physdev --physdev-in %s'
        port_sg_rules = self._get_port_sg_rules(port)
        if self._are_sg_rules_stateful(port_sg_rules):
            # comment to prevent duplicate warnings for different devices using
            # same bridge. truncate start to remove prefixes
            comment = 'Set zone for %s' % self._get_port_device_name(port)
            conntrack = '--zone %s' % self.ipconntrack.get_device_zone(port)
        else:
            comment = 'Make %s stateless' % self._get_port_device_name(port)
            conntrack = '--notrack'
        rules = []
        for dev, match in ((br_dev, match_physdev), (br_dev, match_interface),
                           (port_dev, match_physdev)):
            match = match % dev
            rule = '%s -m comment --comment "%s" -j CT %s' % (match, comment,
                                                              conntrack)
            rules.append(rule)
        return rules

    def _get_port_sg_rules(self, port):
        port_sg_rules = []
        if not any(port.get('device_owner', '').startswith(prefix)
                   for prefix in constants.DEVICE_OWNER_PREFIXES):
            port_sg_ids = port.get('security_groups', [])
            if port_sg_ids:
                for rule in self.sg_rules.get(port_sg_ids[0], []):
                    if self.enable_ipset:
                        port_sg_rules.append(rule)
                        break
                    port_sg_rules.extend(
                        self._expand_sg_rule_with_remote_ips(
                            rule, port, constants.INGRESS_DIRECTION))
                    if port_sg_rules:
                        break
                    port_sg_rules.extend(
                        self._expand_sg_rule_with_remote_ips(
                            rule, port, constants.EGRESS_DIRECTION))
                    if port_sg_rules:
                        break
        return port_sg_rules

    @staticmethod
    def _are_sg_rules_stateful(security_group_rules):
        for rule in security_group_rules:
            return rule.get('stateful', True)
        return True

    def _add_conntrack_jump(self, port):
        for jump_rule in self._get_jump_rules(port):
            self._add_raw_rule('PREROUTING', jump_rule)

    def _remove_conntrack_jump(self, port):
        for jump_rule in self._get_jump_rules(port, create=False):
            self._remove_raw_rule('PREROUTING', jump_rule)

    def _add_raw_rule(self, chain, rule, comment=None):
        self.iptables.ipv4['raw'].add_rule(chain, rule, comment=comment)
        self.iptables.ipv6['raw'].add_rule(chain, rule, comment=comment)

    def _remove_raw_rule(self, chain, rule):
        self.iptables.ipv4['raw'].remove_rule(chain, rule)
        self.iptables.ipv6['raw'].remove_rule(chain, rule)

    def _split_sgr_by_ethertype(self, security_group_rules):
        ipv4_sg_rules = []
        ipv6_sg_rules = []
        for rule in security_group_rules:
            if rule.get('ethertype') == constants.IPv4:
                ipv4_sg_rules.append(rule)
            elif rule.get('ethertype') == constants.IPv6:
                if rule.get('protocol') in const.IPV6_ICMP_LEGACY_PROTO_LIST:
                    rule['protocol'] = constants.PROTO_NAME_IPV6_ICMP
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
                                   % mac.upper(), comment=ic.PAIR_ALLOW)
                else:
                    # we need to convert it into a prefix to match iptables
                    ip = c_utils.ip_to_cidr(ip)
                    table.add_rule(chain_name,
                                   '-s %s -m mac --mac-source %s -j RETURN'
                                   % (ip, mac.upper()), comment=ic.PAIR_ALLOW)
            table.add_rule(chain_name, '-j DROP', comment=ic.PAIR_DROP)
            rules.append('-j $%s' % chain_name)

    def _build_ipv4v6_mac_ip_list(self, mac, ip_address, mac_ipv4_pairs,
                                  mac_ipv6_pairs):
        mac = str(netaddr.EUI(mac, dialect=mac_iptables))
        if netaddr.IPNetwork(ip_address).version == 4:
            mac_ipv4_pairs.append((mac, ip_address))
        else:
            mac_ipv6_pairs.append((mac, ip_address))
            lla = str(netutils.get_ipv6_addr_by_EUI64(
                constants.IPv6_LLA_PREFIX, mac))
            if (mac, lla) not in mac_ipv6_pairs:
                # only add once so we don't generate duplicate rules
                mac_ipv6_pairs.append((mac, lla))

    def _spoofing_rule(self, port, ipv4_rules, ipv6_rules):
        # Fixed rules for traffic sourced from unspecified addresses: 0.0.0.0
        # and ::
        # Allow dhcp client discovery and request
        ipv4_rules += [comment_rule('-s 0.0.0.0/32 -d 255.255.255.255/32 '
                                    '-p udp -m udp --sport 68 --dport 67 '
                                    '-j RETURN', comment=ic.DHCP_CLIENT)]
        # Allow neighbor solicitation and multicast listener discovery
        # from the unspecified address for duplicate address detection
        for icmp6_type in constants.ICMPV6_ALLOWED_UNSPEC_ADDR_TYPES:
            ipv6_rules += [comment_rule('-s ::/128 -d ff02::/16 '
                                        '-p ipv6-icmp -m icmp6 '
                                        '--icmpv6-type %s -j RETURN' %
                                        icmp6_type,
                                        comment=ic.IPV6_ICMP_ALLOW)]
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
        # Fixed rules for traffic after source address is verified
        # Allow dhcp client renewal and rebinding
        ipv4_rules += [comment_rule('-p udp -m udp --sport 68 --dport 67 '
                                    '-j RETURN', comment=ic.DHCP_CLIENT)]
        # Drop Router Advts from the port.
        ipv6_rules += [comment_rule('-p ipv6-icmp -m icmp6 --icmpv6-type %s '
                                    '-j DROP' % constants.ICMPV6_TYPE_RA,
                                    comment=ic.IPV6_RA_DROP)]
        ipv6_rules += [comment_rule('-p ipv6-icmp -j RETURN',
                                    comment=ic.IPV6_ICMP_ALLOW)]
        ipv6_rules += [comment_rule('-p udp -m udp --sport 546 '
                                    '--dport 547 '
                                    '-j RETURN', comment=ic.DHCP_CLIENT)]

    def _drop_dhcp_rule(self, ipv4_rules, ipv6_rules):
        # Note(nati) Drop dhcp packet from VM
        ipv4_rules += [comment_rule('-p udp -m udp --sport 67 '
                                    '--dport 68 '
                                    '-j DROP', comment=ic.DHCP_SPOOF)]
        ipv6_rules += [comment_rule('-p udp -m udp --sport 547 '
                                    '--dport 546 '
                                    '-j DROP', comment=ic.DHCP_SPOOF)]

    def _accept_inbound_icmpv6(self):
        # Allow multicast listener, neighbor solicitation and
        # neighbor advertisement into the instance
        icmpv6_rules = []
        for icmp6_type in firewall.ICMPV6_ALLOWED_INGRESS_TYPES:
            icmpv6_rules += ['-p ipv6-icmp -m icmp6 --icmpv6-type %s '
                             '-j RETURN' % icmp6_type]
        return icmpv6_rules

    def _select_sg_rules_for_port(self, port, direction):
        """Select rules from the security groups the port is member of."""
        port_sg_ids = port.get('security_groups', [])
        port_rules = []

        for sg_id in port_sg_ids:
            for rule in self.sg_rules.get(sg_id, []):
                if rule['direction'] == direction:
                    if self.enable_ipset:
                        port_rules.append(rule)
                    else:
                        port_rules.extend(
                            self._expand_sg_rule_with_remote_ips(
                                rule, port, direction))
        return port_rules

    def _expand_sg_rule_with_remote_ips(self, rule, port, direction):
        """Expand a remote group rule to rule per remote group IP."""
        remote_group_id = rule.get('remote_group_id')
        if remote_group_id:
            ethertype = rule['ethertype']
            port_ips = port.get('fixed_ips', [])

            for ip, _mac in self.sg_members[remote_group_id][ethertype]:
                if ip not in port_ips:
                    ip_rule = rule.copy()
                    direction_ip_prefix = firewall.DIRECTION_IP_PREFIX[
                        direction]
                    ip_prefix = str(netaddr.IPNetwork(ip).cidr)
                    ip_rule[direction_ip_prefix] = ip_prefix
                    yield ip_rule
        else:
            yield rule

    def _get_remote_sg_ids(self, port, direction=None):
        sg_ids = port.get('security_groups', [])
        remote_sg_ids = {constants.IPv4: set(), constants.IPv6: set()}
        for sg_id in sg_ids:
            for rule in self.sg_rules.get(sg_id, []):
                if not direction or rule['direction'] == direction:
                    remote_sg_id = rule.get('remote_group_id')
                    ether_type = rule.get('ethertype')
                    if remote_sg_id and ether_type:
                        remote_sg_ids[ether_type].add(remote_sg_id)
        return remote_sg_ids

    def _add_rules_by_security_group(self, port, direction):
        # select rules for current port and direction
        security_group_rules = self._select_sgr_by_direction(port, direction)
        security_group_rules += self._select_sg_rules_for_port(port, direction)
        # split groups by ip version
        # for ipv4, iptables command is used
        # for ipv6, iptables6 command is used
        ipv4_sg_rules, ipv6_sg_rules = self._split_sgr_by_ethertype(
            security_group_rules)
        ipv4_iptables_rules = []
        ipv6_iptables_rules = []
        # include fixed egress/ingress rules
        if direction == constants.EGRESS_DIRECTION:
            self._add_fixed_egress_rules(port,
                                         ipv4_iptables_rules,
                                         ipv6_iptables_rules)
        elif direction == constants.INGRESS_DIRECTION:
            ipv6_iptables_rules += self._accept_inbound_icmpv6()
        # include IPv4 and IPv6 iptable rules from security group
        ipv4_iptables_rules += self._convert_sgr_to_iptables_rules(
            ipv4_sg_rules)
        ipv6_iptables_rules += self._convert_sgr_to_iptables_rules(
            ipv6_sg_rules)
        # finally add the rules to the port chain for a given direction
        self._add_rules_to_chain_v4v6(self._port_chain_name(port, direction),
                                      ipv4_iptables_rules,
                                      ipv6_iptables_rules)

    def _add_fixed_egress_rules(self, port, ipv4_iptables_rules,
                                ipv6_iptables_rules):
        self._spoofing_rule(port,
                            ipv4_iptables_rules,
                            ipv6_iptables_rules)
        self._drop_dhcp_rule(ipv4_iptables_rules, ipv6_iptables_rules)

    def _generate_ipset_rule_args(self, sg_rule, remote_gid):
        ethertype = sg_rule.get('ethertype')
        ipset_name = self.ipset.get_name(remote_gid, ethertype)
        if not self.ipset.set_name_exists(ipset_name):
            # NOTE(mangelajo): ipsets for empty groups are not created
            #                  thus we can't reference them.
            return None
        ipset_direction = IPSET_DIRECTION[sg_rule.get('direction')]
        args = self._generate_protocol_and_port_args(sg_rule)
        args += ['-m set', '--match-set', ipset_name, ipset_direction]
        args += ['-j RETURN']
        return args

    def _generate_protocol_and_port_args(self, sg_rule):
        is_port = (sg_rule.get('source_port_range_min') is not None or
                   sg_rule.get('port_range_min') is not None)
        args = self._protocol_arg(sg_rule.get('protocol'), is_port)
        args += self._port_arg('sport',
                               sg_rule.get('protocol'),
                               sg_rule.get('source_port_range_min'),
                               sg_rule.get('source_port_range_max'))
        args += self._port_arg('dport',
                               sg_rule.get('protocol'),
                               sg_rule.get('port_range_min'),
                               sg_rule.get('port_range_max'))
        return args

    def _generate_plain_rule_args(self, sg_rule):
        # These arguments MUST be in the format iptables-save will
        # display them: source/dest, protocol, sport, dport, target
        # Otherwise the iptables_manager code won't be able to find
        # them to preserve their [packet:byte] counts.
        args = self._ip_prefix_arg('s', sg_rule.get('source_ip_prefix'))
        args += self._ip_prefix_arg('d', sg_rule.get('dest_ip_prefix'))
        args += self._generate_protocol_and_port_args(sg_rule)
        args += ['-j RETURN']
        return args

    def _convert_sg_rule_to_iptables_args(self, sg_rule):
        remote_gid = sg_rule.get('remote_group_id')
        if self.enable_ipset and remote_gid:
            return self._generate_ipset_rule_args(sg_rule, remote_gid)
        else:
            return self._generate_plain_rule_args(sg_rule)

    def _convert_sgr_to_iptables_rules(self, security_group_rules):
        iptables_rules = []
        self._allow_established(iptables_rules)
        seen_sg_rules = set()
        for rule in security_group_rules:
            args = self._convert_sg_rule_to_iptables_args(rule)
            if args:
                rule_command = ' '.join(args)
                if rule_command in seen_sg_rules:
                    # since these rules are from multiple security groups,
                    # there may be duplicates so we prune them out here
                    continue
                seen_sg_rules.add(rule_command)
                iptables_rules.append(rule_command)

        self._drop_invalid_packets(iptables_rules)
        iptables_rules += [comment_rule('-j $sg-fallback',
                                        comment=ic.UNMATCHED)]
        return iptables_rules

    def _drop_invalid_packets(self, iptables_rules):
        # Always drop invalid packets
        iptables_rules += [comment_rule('-m state --state ' 'INVALID -j DROP',
                                        comment=ic.INVALID_DROP)]
        return iptables_rules

    def _allow_established(self, iptables_rules):
        # Allow established connections
        iptables_rules += [comment_rule(
            '-m state --state RELATED,ESTABLISHED -j RETURN',
            comment=ic.ALLOW_ASSOC)]
        return iptables_rules

    def _local_protocol_name_map(self):
        local_protocol_name_map = {}
        try:
            class protoent(ctypes.Structure):
                _fields_ = [("p_name", ctypes.c_char_p),
                            ("p_aliases", ctypes.POINTER(ctypes.c_char_p)),
                            ("p_proto", ctypes.c_int)]
            libc.getprotoent.restype = ctypes.POINTER(protoent)
            libc.setprotoent(0)
            while True:
                pr = libc.getprotoent()
                if not pr:
                    break
                r = pr[0]
                p_name = helpers.safe_decode_utf8(r.p_name)
                local_protocol_name_map[str(r.p_proto)] = p_name
        except Exception:
            LOG.exception("Unable to create local protocol name map: %s",
                          sys.exc_info()[0])
        finally:
            libc.endprotoent()
        return local_protocol_name_map

    def _protocol_name_map(self):
        if not self._iptables_protocol_name_map:
            tmp_map = constants.IPTABLES_PROTOCOL_NAME_MAP.copy()
            tmp_map.update(self._local_protocol_name_map())
            self._iptables_protocol_name_map = tmp_map
        return self._iptables_protocol_name_map

    def _iptables_protocol_name(self, protocol):
        # protocol zero is a special case and requires no '-p'
        if protocol and protocol != '0':
            return self._protocol_name_map().get(protocol, protocol)

    def _protocol_arg(self, protocol, is_port):
        iptables_rule = []
        rule_protocol = self._iptables_protocol_name(protocol)
        # protocol zero is a special case and requires no '-p'
        if rule_protocol:
            iptables_rule = ['-p', rule_protocol]

            if (is_port and rule_protocol in constants.IPTABLES_PROTOCOL_MAP):
                # iptables adds '-m protocol' when the port number is specified
                iptables_rule += [
                    '-m', constants.IPTABLES_PROTOCOL_MAP[rule_protocol]
                ]
        return iptables_rule

    def _port_arg(self, direction, protocol, port_range_min, port_range_max):
        args = []
        if port_range_min is None:
            return args

        protocol = self._iptables_protocol_name(protocol)
        if protocol in ['icmp', 'ipv6-icmp']:
            protocol_type = 'icmpv6' if protocol == 'ipv6-icmp' else 'icmp'
            # Note(xuhanp): port_range_min/port_range_max represent
            # icmp type/code when protocol is icmp or icmpv6
            args += ['--%s-type' % protocol_type, '%s' % port_range_min]
            # icmp code can be 0 so we cannot use "if port_range_max" here
            if port_range_max is not None:
                args[-1] += '/%s' % port_range_max
        elif protocol in const.SG_PORT_PROTO_NAMES:
            # iptables protocols that support --dport, --sport and -m multiport
            if port_range_min == port_range_max:
                if protocol in const.IPTABLES_MULTIPORT_ONLY_PROTOCOLS:
                    # use -m multiport, but without a port range
                    args += ['-m', 'multiport', '--%ss' % direction,
                             '%s' % port_range_min]
                else:
                    args += ['--%s' % direction, '%s' % port_range_min]
            else:
                args += ['-m', 'multiport', '--%ss' % direction,
                         '%s:%s' % (port_range_min, port_range_max)]
        return args

    def _ip_prefix_arg(self, direction, ip_prefix):
        # NOTE (nati) : source_group_id is converted to list of source_
        # ip_prefix in server side
        if ip_prefix:
            if '/' not in ip_prefix:
                # we need to convert it into a prefix to match iptables
                ip_prefix = c_utils.ip_to_cidr(ip_prefix)
            elif ip_prefix.endswith('/0'):
                # an allow for every address is not a constraint so
                # iptables drops it
                return []
            return ['-%s' % direction, ip_prefix]
        return []

    def _port_chain_name(self, port, direction):
        return iptables_manager.get_chain_name(
            '%s%s' % (CHAIN_NAME_PREFIX[direction], port['device'][3:]))

    def filter_defer_apply_on(self):
        if not self._defer_apply:
            self.iptables.defer_apply_on()
            self._pre_defer_filtered_ports = dict(self.filtered_ports)
            self._pre_defer_unfiltered_ports = dict(self.unfiltered_ports)
            self.pre_sg_members = dict(self.sg_members)
            self.pre_sg_rules = dict(self.sg_rules)
            self._defer_apply = True

    def _remove_unused_security_group_info(self):
        """Remove any unnecessary local security group info or unused ipsets.

        This function has to be called after applying the last iptables
        rules, so we're in a point where no iptable rule depends
        on an ipset we're going to delete.
        """
        filtered_ports = self.filtered_ports.values()

        remote_sgs_to_remove = self._determine_remote_sgs_to_remove(
            filtered_ports)

        for ip_version, remote_sg_ids in remote_sgs_to_remove.items():
            if self.enable_ipset:
                self._remove_ipsets_for_remote_sgs(ip_version, remote_sg_ids)

        self._remove_sg_members(remote_sgs_to_remove)

        # Remove unused security group rules
        for remove_group_id in self._determine_sg_rules_to_remove(
                filtered_ports):
            self.sg_rules.pop(remove_group_id, None)

    def _determine_remote_sgs_to_remove(self, filtered_ports):
        """Calculate which remote security groups we don't need anymore.

        We do the calculation for each ip_version.
        """
        sgs_to_remove_per_ipversion = {constants.IPv4: set(),
                                       constants.IPv6: set()}
        remote_group_id_sets = self._get_remote_sg_ids_sets_by_ipversion(
            filtered_ports)
        for ip_version, remote_group_id_set in remote_group_id_sets.items():
            sgs_to_remove_per_ipversion[ip_version].update(
                set(self.pre_sg_members) - remote_group_id_set)
        return sgs_to_remove_per_ipversion

    def _get_remote_sg_ids_sets_by_ipversion(self, filtered_ports):
        """Given a port, calculates the remote sg references by ip_version."""
        remote_group_id_sets = {constants.IPv4: set(),
                                constants.IPv6: set()}
        for port in filtered_ports:
            remote_sg_ids = self._get_remote_sg_ids(port)
            for ip_version in (constants.IPv4, constants.IPv6):
                remote_group_id_sets[ip_version] |= remote_sg_ids[ip_version]
        return remote_group_id_sets

    def _determine_sg_rules_to_remove(self, filtered_ports):
        """Calculate which security groups need to be removed.

        We find out by subtracting our previous sg group ids,
        with the security groups associated to a set of ports.
        """
        port_group_ids = self._get_sg_ids_set_for_ports(filtered_ports)
        return set(self.pre_sg_rules) - port_group_ids

    def _get_sg_ids_set_for_ports(self, filtered_ports):
        """Get the port security group ids as a set."""
        port_group_ids = set()
        for port in filtered_ports:
            port_group_ids.update(port.get('security_groups', []))
        return port_group_ids

    def _remove_ipsets_for_remote_sgs(self, ip_version, remote_sg_ids):
        """Remove system ipsets matching the provided parameters."""
        for remote_sg_id in remote_sg_ids:
            self.ipset.destroy(remote_sg_id, ip_version)

    def _remove_sg_members(self, remote_sgs_to_remove):
        """Remove sg_member entries."""
        ipv4_sec_group_set = remote_sgs_to_remove.get(constants.IPv4)
        ipv6_sec_group_set = remote_sgs_to_remove.get(constants.IPv6)
        for sg_id in (ipv4_sec_group_set & ipv6_sec_group_set):
            if sg_id in self.sg_members:
                del self.sg_members[sg_id]

    def _find_deleted_sg_rules(self, sg_id):
        del_rules = list()
        for pre_rule in self.pre_sg_rules.get(sg_id, []):
            if pre_rule not in self.sg_rules.get(sg_id, []):
                del_rules.append(pre_rule)
        return del_rules

    def _find_devices_on_security_group(self, sg_id):
        device_list = list()
        for device in self.filtered_ports.values():
            if sg_id in device.get('security_groups', []):
                device_list.append(device)
        return device_list

    def _clean_deleted_sg_rule_conntrack_entries(self):
        deleted_sg_ids = set()
        for sg_id in set(self.updated_rule_sg_ids):
            del_rules = self._find_deleted_sg_rules(sg_id)
            if not del_rules:
                continue
            device_list = self._find_devices_on_security_group(sg_id)
            for rule in del_rules:
                self.ipconntrack.delete_conntrack_state_by_rule(
                    device_list, rule)
            deleted_sg_ids.add(sg_id)
        for id in deleted_sg_ids:
            self.updated_rule_sg_ids.remove(id)

    def _clean_updated_sg_member_conntrack_entries(self):
        updated_device_ids = set()
        for device in set(self.updated_sg_members):
            sec_group_change = False
            device_info = self.filtered_ports.get(device)
            pre_device_info = self._pre_defer_filtered_ports.get(device)
            if not device_info or not pre_device_info:
                continue
            for sg_id in pre_device_info.get('security_groups', []):
                if sg_id not in device_info.get('security_groups', []):
                    sec_group_change = True
                    break
            if not sec_group_change:
                continue
            for ethertype in [constants.IPv4, constants.IPv6]:
                self.ipconntrack.delete_conntrack_state_by_remote_ips(
                    [device_info], ethertype, set())
            updated_device_ids.add(device)
        for id in updated_device_ids:
            self.updated_sg_members.remove(id)

    def _clean_deleted_remote_sg_members_conntrack_entries(self):
        deleted_sg_ids = set()
        for sg_id, devices in self.devices_with_updated_sg_members.items():
            for ethertype in [constants.IPv4, constants.IPv6]:
                pre_ips = self._get_sg_members(
                    self.pre_sg_members, sg_id, ethertype)
                cur_ips = self._get_sg_members(
                    self.sg_members, sg_id, ethertype)
                ips = (pre_ips - cur_ips)
                if devices and ips:
                    self.ipconntrack.delete_conntrack_state_by_remote_ips(
                        devices, ethertype, ips)
            deleted_sg_ids.add(sg_id)
        for id in deleted_sg_ids:
            self.devices_with_updated_sg_members.pop(id, None)

    def _remove_conntrack_entries_from_sg_updates(self):
        self._clean_deleted_sg_rule_conntrack_entries()
        self._clean_updated_sg_member_conntrack_entries()
        if not self.enable_ipset:
            self._clean_deleted_remote_sg_members_conntrack_entries()

    def _get_sg_members(self, sg_info, sg_id, ethertype):
        ip_mac_addresses = sg_info.get(sg_id, {}).get(ethertype, [])
        return set([ip_mac[0] for ip_mac in ip_mac_addresses])

    def filter_defer_apply_off(self):
        if self._defer_apply:
            self._defer_apply = False
            self._remove_chains_apply(self._pre_defer_filtered_ports,
                                      self._pre_defer_unfiltered_ports)
            self._setup_chains_apply(self.filtered_ports,
                                     self.unfiltered_ports)
            self.iptables.defer_apply_off()
            self._remove_conntrack_entries_from_sg_updates()
            self._remove_unused_security_group_info()
            self._pre_defer_filtered_ports = None
            self._pre_defer_unfiltered_ports = None


class OVSHybridIptablesFirewallDriver(IptablesFirewallDriver):
    OVS_HYBRID_PLUG_REQUIRED = True
    CONNTRACK_ZONE_PER_PORT = True

    def _port_chain_name(self, port, direction):
        return iptables_manager.get_chain_name(
            '%s%s' % (CHAIN_NAME_PREFIX[direction], port['device']))

    def _get_br_device_name(self, port):
        return ('qvb' + port['device'])[:constants.LINUX_DEV_LEN]

    def _get_device_name(self, port):
        device_name = super(
            OVSHybridIptablesFirewallDriver, self)._get_device_name(port)
        return get_hybrid_port_name(device_name)
