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

import abc
import contextlib

import six


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

    def prepare_port_filter(self, port):
        """Prepare filters for the port.

        This method should be called before the port is created.
        """
        raise NotImplementedError()

    def apply_port_filter(self, port):
        """Apply port filter.

        Once this method returns, the port should be firewalled
        appropriately. This method should as far as possible be a
        no-op. It's vastly preferred to get everything set up in
        prepare_port_filter.
        """
        raise NotImplementedError()

    def update_port_filter(self, port):
        """Refresh security group rules from data store

        Gets called when an port gets added to or removed from
        the security group the port is a member of or if the
        group gains or looses a rule.
        """
        raise NotImplementedError()

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
