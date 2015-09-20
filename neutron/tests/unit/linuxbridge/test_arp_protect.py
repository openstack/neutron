# Copyright (c) 2015 Cisco Systems, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import contextlib
import copy
import mock

from oslo.config import cfg

from neutron.plugins.linuxbridge.agent import arp_protect
from neutron.tests import base


class ArpProtectTestCase(base.BaseTestCase):

    VIF = 'tap3fc5bc14-b1'
    FIXED_IP = '1.2.3.4'
    ALLOWED_ADDRESS = '5.6.7.8'
    CHAIN_NAME = arp_protect.chain_name(VIF)

    EBTABLES_EMPTY_SAMPLE = [
        'Bridge table: filter',
        '',
        'Bridge chain: INPUT, entries: 0, policy: ACCEPT',
        '',
        'Bridge chain: FORWARD, entries: 0, policy: ACCEPT',
        '',
        'Bridge chain: OUTPUT, entries: 0, policy: ACCEPT',
    ]

    EBTABLES_LOADED_SAMPLE = [
        'Bridge table: filter',
        '',
        'Bridge chain: INPUT, entries: 0, policy: ACCEPT',
        '',
        'Bridge chain: FORWARD, entries: 2, policy: ACCEPT',
        '-p ARP -i %s -j %s' % (VIF, CHAIN_NAME),
        '',
        'Bridge chain: OUTPUT, entries: 0, policy: ACCEPT',
        '',
        'Bridge chain: %s, entries: 1, policy: DROP' % (CHAIN_NAME),
        '-p ARP --arp-ip-src %s -j ACCEPT' % (FIXED_IP),
    ]
    PORT_DETAILS_SAMPLE = {
        'port_security_enabled': True,
        'fixed_ips': [{
            'subnet_id': '12345',
            'ip_address': FIXED_IP,
        }],
        'allowed_address_pairs': [],
        'device_owner': 'nobody',
    }

    def setUp(self):
        super(ArpProtectTestCase, self).setUp()
        cfg.CONF.set_override('prevent_arp_spoofing', True, 'AGENT')

    def _do_test_setup_arp_spoofing(self, vif, port_details):
        with contextlib.nested(
            mock.patch.object(
                arp_protect, 'ebtables',
                return_value='\n'.join(self.EBTABLES_EMPTY_SAMPLE)
            )
        ) as ebtables_fn:       # noqa
            arp_protect.setup_arp_spoofing_protection(vif, port_details)

    def test_setup_arp_spoofing(self):
        port_details = copy.deepcopy(self.PORT_DETAILS_SAMPLE)
        with contextlib.nested(
            mock.patch.object(arp_protect, 'install_arp_spoofing_protection'),
            mock.patch.object(arp_protect, 'delete_arp_spoofing_protection'),
        ) as (install_fn, delete_fn):
            self._do_test_setup_arp_spoofing(self.VIF, port_details)
            self.assertFalse(delete_fn.called)
            install_fn.assert_called_once_with(self.VIF,
                                               set([self.FIXED_IP]),
                                               self.EBTABLES_EMPTY_SAMPLE)

    def test_setup_arp_spoofing_with_allowed_address_pairs(self):
        port_details = copy.deepcopy(self.PORT_DETAILS_SAMPLE)
        port_details['allowed_address_pairs'] = [{
            'mac_address': 'aa:bb:cc:dd:ee:ff',
            'ip_address': '5.6.7.8',
        }]
        with contextlib.nested(
            mock.patch.object(arp_protect, 'install_arp_spoofing_protection'),
            mock.patch.object(arp_protect, 'delete_arp_spoofing_protection'),
        ) as (install_fn, delete_fn):
            self._do_test_setup_arp_spoofing(self.VIF, port_details)
            self.assertFalse(delete_fn.called)
            install_fn.assert_called_once_with(self.VIF,
                                               set([self.FIXED_IP,
                                                    self.ALLOWED_ADDRESS]),
                                               self.EBTABLES_EMPTY_SAMPLE)

    def test_setup_arp_spoofing_no_pse(self):
        port_details = copy.deepcopy(self.PORT_DETAILS_SAMPLE)
        port_details['port_security_enabled'] = False
        with contextlib.nested(
            mock.patch.object(arp_protect, 'install_arp_spoofing_protection'),
            mock.patch.object(arp_protect, 'delete_arp_spoofing_protection'),
        ) as (install_fn, delete_fn):
            self._do_test_setup_arp_spoofing(self.VIF, port_details)
            delete_fn.assert_called_once_with([self.VIF],
                                              self.EBTABLES_EMPTY_SAMPLE)
            self.assertFalse(install_fn.called)

    def test_setup_arp_spoofing_network_port(self):
        port_details = copy.deepcopy(self.PORT_DETAILS_SAMPLE)
        port_details['device_owner'] = 'network:router_gateway'
        with contextlib.nested(
            mock.patch.object(arp_protect, 'install_arp_spoofing_protection'),
            mock.patch.object(arp_protect, 'delete_arp_spoofing_protection'),
        ) as (install_fn, delete_fn):
            self._do_test_setup_arp_spoofing(self.VIF, port_details)
            delete_fn.assert_called_once_with([self.VIF],
                                              self.EBTABLES_EMPTY_SAMPLE)
            self.assertFalse(install_fn.called)

    def test_setup_arp_spoofing_zero_length_prefix(self):
        port_details = copy.deepcopy(self.PORT_DETAILS_SAMPLE)
        port_details['allowed_address_pairs'] = [{
            'mac_address': 'aa:bb:cc:dd:ee:ff',
            'ip_address': '0.0.0.0/0',
        }]
        with contextlib.nested(
            mock.patch.object(arp_protect, 'install_arp_spoofing_protection'),
            mock.patch.object(arp_protect, 'delete_arp_spoofing_protection'),
        ) as (install_fn, delete_fn):
            self._do_test_setup_arp_spoofing(self.VIF, port_details)
            self.assertFalse(delete_fn.called)
            self.assertFalse(install_fn.called)

    def test_chain_name(self):
        name = '%s%s' % (arp_protect.SPOOF_CHAIN_PREFIX, self.VIF)
        self.assertEqual(name, arp_protect.chain_name(self.VIF))

    def test_delete_arp_spoofing(self):
        # Note(cfb): We don't call this with contextlib.nested() because
        # arp_protect.delete_arp_spoofing_protection() has a decorator
        # which is a non-nested context manager and they don't play nice
        # together with mock at all.
        ebtables_p = mock.patch.object(arp_protect, 'ebtables')
        ebtables = ebtables_p.start()

        arp_protect.delete_arp_spoofing_protection(
            [self.VIF], current_rules=self.EBTABLES_LOADED_SAMPLE)
        expected = [
            mock.call(['-D', 'FORWARD', '-i', self.VIF, '-j',
                       self.CHAIN_NAME, '-p', 'ARP']),
            mock.call(['-X', self.CHAIN_NAME]),
        ]
        ebtables.assert_has_calls(expected)

    def test_delete_unreferenced_arp(self):
        with contextlib.nested(
            mock.patch.object(
                arp_protect, 'ebtables',
                return_value='\n'.join(self.EBTABLES_LOADED_SAMPLE)),
            mock.patch.object(arp_protect, 'delete_arp_spoofing_protection'),
        ) as (ebtables_fn, delete_fn):
            arp_protect.delete_unreferenced_arp_protection([])
            delete_fn.assert_called_once_with([self.VIF],
                                              self.EBTABLES_LOADED_SAMPLE)

    def test_install_arp_spoofing_single_ip(self):
        # Note(cfb): We don't call this with contextlib.nested() because
        # arp_protect.install.arp_spoofing_protection() has a decorator
        # which is a non-nested context manager and they don't play nice
        # together with mock at all.
        ebtables_p = mock.patch.object(arp_protect, 'ebtables')
        ebtables = ebtables_p.start()

        arp_protect.install_arp_spoofing_protection(
            self.VIF, [self.FIXED_IP], self.EBTABLES_EMPTY_SAMPLE)
        expected = [
            mock.call(['-N', self.CHAIN_NAME, '-P', 'DROP']),
            mock.call(['-F', self.CHAIN_NAME]),
            mock.call(['-A', self.CHAIN_NAME, '-p', 'ARP',
                       '--arp-ip-src', self.FIXED_IP, '-j', 'ACCEPT']),
            mock.call(['-A', 'FORWARD', '-i', self.VIF, '-j',
                       self.CHAIN_NAME, '-p', 'ARP']),
        ]
        ebtables.assert_has_calls(expected)

    def test_install_arp_spoofing_multiple_ip(self):
        # Note(cfb): We don't call this with contextlib.nested() because
        # arp_protect.install.arp_spoofing_protection() has a decorator
        # which is a non-nested context manager and they don't play nice
        # together with mock at all.
        ebtables_p = mock.patch.object(arp_protect, 'ebtables')
        ebtables = ebtables_p.start()

        arp_protect.install_arp_spoofing_protection(
            self.VIF, [self.FIXED_IP, self.ALLOWED_ADDRESS],
            self.EBTABLES_EMPTY_SAMPLE)
        expected = [
            mock.call(['-N', self.CHAIN_NAME, '-P', 'DROP']),
            mock.call(['-F', self.CHAIN_NAME]),
            mock.call(['-A', self.CHAIN_NAME, '-p', 'ARP',
                       '--arp-ip-src', self.FIXED_IP, '-j', 'ACCEPT']),
            mock.call(['-A', self.CHAIN_NAME, '-p', 'ARP',
                       '--arp-ip-src', self.ALLOWED_ADDRESS, '-j', 'ACCEPT']),
            mock.call(['-A', 'FORWARD', '-i', self.VIF, '-j',
                       self.CHAIN_NAME, '-p', 'ARP']),
        ]
        ebtables.assert_has_calls(expected)

    def test_install_arp_spoofing_existing_chain(self):
        # Note(cfb): We don't call this with contextlib.nested() because
        # arp_protect.install.arp_spoofing_protection() has a decorator
        # which is a non-nested context manager and they don't play nice
        # together with mock at all.
        ebtables_p = mock.patch.object(arp_protect, 'ebtables')
        ebtables = ebtables_p.start()

        current_rules = [
            'Bridge table: filter',
            '',
            'Bridge chain: INPUT, entries: 0, policy: ACCEPT',
            '',
            'Bridge chain: FORWARD, entries: 2, policy: ACCEPT',
            '',
            'Bridge chain: OUTPUT, entries: 0, policy: ACCEPT',
            '',
            'Bridge chain: %s, entries: 1, policy: DROP' % (self.CHAIN_NAME),
        ]

        arp_protect.install_arp_spoofing_protection(self.VIF,
                                                    [self.FIXED_IP],
                                                    current_rules)
        expected = [
            mock.call(['-F', self.CHAIN_NAME]),
            mock.call(['-A', self.CHAIN_NAME, '-p', 'ARP',
                       '--arp-ip-src', self.FIXED_IP, '-j', 'ACCEPT']),
            mock.call(['-A', 'FORWARD', '-i', self.VIF, '-j',
                       self.CHAIN_NAME, '-p', 'ARP']),
        ]
        ebtables.assert_has_calls(expected)

    def test_install_arp_spoofing_existing_jump(self):
        # Note(cfb): We don't call this with contextlib.nested() because
        # arp_protect.install.arp_spoofing_protection() has a decorator
        # which is a non-nested context manager and they don't play nice
        # together with mock at all.
        ebtables_p = mock.patch.object(arp_protect, 'ebtables')
        ebtables = ebtables_p.start()

        current_rules = [
            'Bridge table: filter',
            '',
            'Bridge chain: INPUT, entries: 0, policy: ACCEPT',
            '',
            'Bridge chain: FORWARD, entries: 2, policy: ACCEPT',
            '-p ARP -i %s -j %s' % (self.VIF, self.CHAIN_NAME),
            '',
            'Bridge chain: OUTPUT, entries: 0, policy: ACCEPT',
            '',
        ]

        arp_protect.install_arp_spoofing_protection(self.VIF,
                                                    [self.FIXED_IP],
                                                    current_rules)
        expected = [
            mock.call(['-N', self.CHAIN_NAME, '-P', 'DROP']),
            mock.call(['-F', self.CHAIN_NAME]),
            mock.call(['-A', self.CHAIN_NAME, '-p', 'ARP',
                       '--arp-ip-src', self.FIXED_IP, '-j', 'ACCEPT']),
        ]
        ebtables.assert_has_calls(expected)

    def test_chain_exists(self):
        self.assertTrue(arp_protect.chain_exists(self.CHAIN_NAME,
                                                 self.EBTABLES_LOADED_SAMPLE))

    def test_chain_does_not_exist(self):
        self.assertFalse(arp_protect.chain_exists('foobarbaz',
                                                  self.EBTABLES_LOADED_SAMPLE))

    def test_vif_jump_present(self):
        self.assertTrue(arp_protect.vif_jump_present(
            self.VIF, self.EBTABLES_LOADED_SAMPLE))

    def test_vif_jump_not_present(self):
        self.assertFalse(arp_protect.vif_jump_present(
            'foobarbaz', self.EBTABLES_LOADED_SAMPLE))
