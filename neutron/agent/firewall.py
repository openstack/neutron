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

import abc
import contextlib

import six

from neutron_lib.api.definitions import port_security as psec
from neutron_lib import constants as n_const
from neutron_lib.utils import runtime


DIRECTION_IP_PREFIX = {n_const.INGRESS_DIRECTION: 'source_ip_prefix',
                       n_const.EGRESS_DIRECTION: 'dest_ip_prefix'}

# List of ICMPv6 types that should be permitted (ingress) by default. This list
# depends on iptables conntrack behavior of recognizing ICMP errors (types 1-4)
# as related traffic.
ICMPV6_ALLOWED_INGRESS_TYPES = (n_const.ICMPV6_TYPE_MLD_QUERY,
                                n_const.ICMPV6_TYPE_NS,
                                n_const.ICMPV6_TYPE_NA)

# List of ICMPv6 types that should be permitted (egress) by default.
ICMPV6_ALLOWED_EGRESS_TYPES = (n_const.ICMPV6_TYPE_MLD_QUERY,
                               n_const.ICMPV6_TYPE_RS,
                               n_const.ICMPV6_TYPE_NS,
                               n_const.ICMPV6_TYPE_NA)


def port_sec_enabled(port):
    return port.get(psec.PORTSECURITY, True)


def load_firewall_driver_class(driver):
    return runtime.load_class_by_alias_or_classname(
        'neutron.agent.firewall_drivers', driver)


@six.add_metaclass(abc.ABCMeta)
class FirewallDriver(object):
    """Firewall Driver base class.

    Defines methods that any driver providing security groups
    and provider firewall functionality should implement.
    Note port attribute should have information of security group ids and
    security group rules.

    the dict of port should have
      device : interface name
      fixed_ips: ips of the device
      mac_address: mac_address of the device
      security_groups: [sgid, sgid]
      security_group_rules : [ rule, rule ]
      the rule must contain ethertype and direction
      the rule may contain security_group_id,
          protocol, port_min, port_max
          source_ip_prefix, source_port_min,
          source_port_max, dest_ip_prefix, and
          remote_group_id
      Note: source_group_ip in REST API should be converted by this rule
      if direction is ingress:
        remote_group_ip will be a source_ip_prefix
      if direction is egress:
        remote_group_ip will be a dest_ip_prefix
      Note: remote_group_id in REST API should be converted by this rule
      if direction is ingress:
        remote_group_id will be a list of source_ip_prefix
      if direction is egress:
        remote_group_id will be a list of dest_ip_prefix
      remote_group_id will also remaining membership update management
    """

    # OVS agent installs arp spoofing openflow rules. If firewall is capable
    # of handling that, ovs agent doesn't need to install the protection.
    provides_arp_spoofing_protection = False

    @abc.abstractmethod
    def prepare_port_filter(self, port):
        """Prepare filters for the port.

        This method should be called before the port is created.
        """

    def apply_port_filter(self, port):
        """Apply port filter.

        Once this method returns, the port should be firewalled
        appropriately. This method should as far as possible be a
        no-op. It's vastly preferred to get everything set up in
        prepare_port_filter.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def update_port_filter(self, port):
        """Refresh security group rules from data store

        Gets called when a port gets added to or removed from
        the security group the port is a member of or if the
        group gains or looses a rule.
        """

    def remove_port_filter(self, port):
        """Stop filtering port."""
        raise NotImplementedError()

    def filter_defer_apply_on(self):
        """Defer application of filtering rule."""
        pass

    def filter_defer_apply_off(self):
        """Turn off deferral of rules and apply the rules now."""
        pass

    @property
    def ports(self):
        """Returns filtered ports."""
        pass

    @contextlib.contextmanager
    def defer_apply(self):
        """Defer apply context."""
        self.filter_defer_apply_on()
        try:
            yield
        finally:
            self.filter_defer_apply_off()

    def update_security_group_members(self, sg_id, ips):
        """Update group members in a security group."""
        raise NotImplementedError()

    def update_security_group_rules(self, sg_id, rules):
        """Update rules in a security group."""
        raise NotImplementedError()

    def security_group_updated(self, action_type, sec_group_ids,
                               device_id=None):
        """Called when a security group is updated.

        Note: This method needs to be implemented by the firewall drivers
        which use enhanced RPC for security_groups.
        """
        raise NotImplementedError()

    def process_trusted_ports(self, port_ids):
        """Process ports that are trusted and shouldn't be filtered."""
        pass

    def remove_trusted_ports(self, port_ids):
        pass


class NoopFirewallDriver(FirewallDriver):
    """Noop Firewall Driver.

    Firewall driver which does nothing.
    This driver is for disabling the firewall functionality.
    """

    def prepare_port_filter(self, port):
        pass

    def apply_port_filter(self, port):
        pass

    def update_port_filter(self, port):
        pass

    def remove_port_filter(self, port):
        pass

    def filter_defer_apply_on(self):
        pass

    def filter_defer_apply_off(self):
        pass

    @property
    def ports(self):
        return {}

    def update_security_group_members(self, sg_id, ips):
        pass

    def update_security_group_rules(self, sg_id, rules):
        pass

    def security_group_updated(self, action_type, sec_group_ids,
                               device_id=None):
        pass
