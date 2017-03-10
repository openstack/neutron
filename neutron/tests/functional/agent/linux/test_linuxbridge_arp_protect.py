# Copyright (c) 2015 Mirantis, Inc.
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

from neutron_lib import constants
from neutron_lib.utils import net

from neutron.plugins.ml2.drivers.linuxbridge.agent import arp_protect
from neutron.tests.common import machine_fixtures
from neutron.tests.common import net_helpers
from neutron.tests.functional import base as functional_base

no_arping = net_helpers.assert_no_arping
arping = net_helpers.assert_arping


class LinuxBridgeARPSpoofTestCase(functional_base.BaseSudoTestCase):

    def setUp(self):
        super(LinuxBridgeARPSpoofTestCase, self).setUp()

        lbfixture = self.useFixture(net_helpers.LinuxBridgeFixture())
        self.addCleanup(setattr, arp_protect, 'NAMESPACE', None)
        arp_protect.NAMESPACE = lbfixture.namespace
        bridge = lbfixture.bridge
        self.source, self.destination, self.observer = self.useFixture(
            machine_fixtures.PeerMachines(bridge, amount=3)).machines
        self.addCleanup(self._ensure_rules_cleaned)

    def _ensure_rules_cleaned(self):
        rules = [r for r in arp_protect.ebtables(['-L']).splitlines()
                 if r and 'Bridge' not in r]
        self.assertEqual([], rules, 'Test leaked ebtables rules')

    def _add_arp_protection(self, machine, addresses, extra_port_dict=None):
        port_dict = {'fixed_ips': [{'ip_address': a} for a in addresses],
                     'device_owner': 'nobody',
                     'mac_address': machine.port.link.address}
        if extra_port_dict:
            port_dict.update(extra_port_dict)
        name = net_helpers.VethFixture.get_peer_name(machine.port.name)
        arp_protect.setup_arp_spoofing_protection(name, port_dict)
        self.addCleanup(arp_protect.delete_arp_spoofing_protection,
                        [name])

    def test_arp_no_protection(self):
        arping(self.source.namespace, self.destination.ip)
        arping(self.destination.namespace, self.source.ip)

    def test_arp_correct_protection(self):
        self._add_arp_protection(self.source, [self.source.ip])
        self._add_arp_protection(self.destination, [self.destination.ip])
        arping(self.source.namespace, self.destination.ip)
        arping(self.destination.namespace, self.source.ip)

    def test_arp_correct_protection_allowed_address_pairs(self):
        smac = self.source.port.link.address
        port = {'mac_address': '00:11:22:33:44:55',
                'allowed_address_pairs': [{'mac_address': smac,
                                           'ip_address': self.source.ip}]}
        # make sure a large number of allowed address pairs works
        for i in range(100000):
            port['allowed_address_pairs'].append(
                {'mac_address': net.get_random_mac(
                     'fa:16:3e:00:00:00'.split(':')),
                 'ip_address': '10.10.10.10'})
        self._add_arp_protection(self.source, ['1.2.2.2'], port)
        self._add_arp_protection(self.destination, [self.destination.ip])
        arping(self.source.namespace, self.destination.ip)
        arping(self.destination.namespace, self.source.ip)

    def test_arp_fails_incorrect_protection(self):
        self._add_arp_protection(self.source, ['1.1.1.1'])
        self._add_arp_protection(self.destination, ['2.2.2.2'])
        no_arping(self.source.namespace, self.destination.ip)
        no_arping(self.destination.namespace, self.source.ip)

    def test_arp_fails_incorrect_mac_protection(self):
        # a bad mac filter on the source will prevent any traffic from it
        self._add_arp_protection(self.source, [self.source.ip],
                                 {'mac_address': '00:11:22:33:44:55'})
        no_arping(self.source.namespace, self.destination.ip)
        no_arping(self.destination.namespace, self.source.ip)
        # correcting it should make it work
        self._add_arp_protection(self.source, [self.source.ip])
        arping(self.source.namespace, self.destination.ip)

    def test_arp_protection_removal(self):
        self._add_arp_protection(self.source, ['1.1.1.1'])
        self._add_arp_protection(self.destination, ['2.2.2.2'])
        no_arping(self.observer.namespace, self.destination.ip)
        no_arping(self.observer.namespace, self.source.ip)
        name = net_helpers.VethFixture.get_peer_name(self.source.port.name)
        arp_protect.delete_arp_spoofing_protection([name])
        # spoofing should have been removed from source, but not dest
        arping(self.observer.namespace, self.source.ip)
        no_arping(self.observer.namespace, self.destination.ip)

    def test_arp_protection_update(self):
        self._add_arp_protection(self.source, ['1.1.1.1'])
        self._add_arp_protection(self.destination, ['2.2.2.2'])
        no_arping(self.observer.namespace, self.destination.ip)
        no_arping(self.observer.namespace, self.source.ip)
        self._add_arp_protection(self.source, ['192.0.0.0/1'])
        # spoofing should have been updated on source, but not dest
        arping(self.observer.namespace, self.source.ip)
        no_arping(self.observer.namespace, self.destination.ip)

    def test_arp_protection_port_security_disabled(self):
        self._add_arp_protection(self.source, ['1.1.1.1'])
        no_arping(self.observer.namespace, self.source.ip)
        self._add_arp_protection(self.source, ['1.1.1.1'],
                                 {'port_security_enabled': False})
        arping(self.observer.namespace, self.source.ip)

    def test_arp_protection_network_owner(self):
        self._add_arp_protection(self.source, ['1.1.1.1'])
        no_arping(self.observer.namespace, self.source.ip)
        self._add_arp_protection(self.source, ['1.1.1.1'],
                                 {'device_owner':
                                  constants.DEVICE_OWNER_ROUTER_GW})
        arping(self.observer.namespace, self.source.ip)

    def test_arp_protection_dead_reference_removal(self):
        self._add_arp_protection(self.source, ['1.1.1.1'])
        self._add_arp_protection(self.destination, ['2.2.2.2'])
        no_arping(self.observer.namespace, self.destination.ip)
        no_arping(self.observer.namespace, self.source.ip)
        name = net_helpers.VethFixture.get_peer_name(self.source.port.name)
        # This should remove all arp protect rules that aren't source port
        arp_protect.delete_unreferenced_arp_protection([name])
        no_arping(self.observer.namespace, self.source.ip)
        arping(self.observer.namespace, self.destination.ip)
