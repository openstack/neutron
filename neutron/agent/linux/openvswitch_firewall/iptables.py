# Copyright 2017 Red Hat, Inc.
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

from neutron_lib import constants as n_const


def get_device_port_name(port_id):
    return ('qvo' + port_id)[:n_const.LINUX_DEV_LEN]


def get_iptables_driver_instance():
    """Load hybrid iptables firewall driver."""
    # pylint: disable=import-outside-toplevel
    from neutron.agent.linux import iptables_firewall

    class HybridIptablesHelper(
            iptables_firewall.OVSHybridIptablesFirewallDriver):
        """Don't remove conntrack when removing iptables rules."""
        def _remove_conntrack_entries_from_port_deleted(self, port):
            pass

    return HybridIptablesHelper()


def is_bridge_cleaned(bridge):
    other_config = bridge.db_get_val(
        'Bridge', bridge.br_name, 'other_config')
    return other_config.get(Helper.CLEANED_METADATA, '').lower() == 'true'


class Helper(object):
    """Helper to avoid loading firewall driver.

    The main purpose is to avoid loading iptables driver for cases where no
    ports have hybrid plugging on given node.

    The helper stores metadata for iptables cleanup into br-int ovsdb Bridge
    table. Specifically it checks for other_config['iptables_cleaned'] boolean
    value.
    """
    HYBRID_PORT_PREFIX = 'qvo'
    CLEANED_METADATA = 'iptables_cleaned'

    def __init__(self, int_br):
        self.int_br = int_br
        self.hybrid_ports = None
        self.iptables_driver = None

    def load_driver_if_needed(self):
        self.hybrid_ports = self.get_hybrid_ports()
        if self.hybrid_ports and self.has_not_been_cleaned:
            self.iptables_driver = get_iptables_driver_instance()

    def get_hybrid_ports(self):
        """Return True if there is a port with hybrid plugging."""
        return {
            port_name for port_name in self.int_br.get_port_name_list()
            if port_name.startswith(self.HYBRID_PORT_PREFIX)}

    def cleanup_port(self, port):
        if not self.iptables_driver:
            return
        device_name = get_device_port_name(port['device'])
        try:
            self.hybrid_ports.remove(device_name)
        except KeyError:
            # It's not a hybrid plugged port
            return

        # TODO(jlibosva): Optimize, add port to firewall without installing
        # iptables rules and then call remove from firewall
        self.iptables_driver.prepare_port_filter(port)
        self.iptables_driver.remove_port_filter(port)
        if not self.hybrid_ports:
            self.mark_as_cleaned()
            # Let GC remove iptables driver
            self.iptables_driver = None

    @property
    def has_not_been_cleaned(self):
        return not is_bridge_cleaned(self.int_br)

    def mark_as_cleaned(self):
        # TODO(jlibosva): Make it a single transaction
        other_config = self.int_br.db_get_val(
            'Bridge', self.int_br.br_name, 'other_config')
        other_config[self.CLEANED_METADATA] = 'true'
        self.int_br.set_db_attribute(
            'Bridge', self.int_br.br_name, 'other_config', other_config)
