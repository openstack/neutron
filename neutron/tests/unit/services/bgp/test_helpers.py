# Copyright 2025 Red Hat, Inc.
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

from neutron.services.bgp import helpers
from neutron.tests import base


class LrpMacManagerTestCase(base.BaseTestCase):
    def setUp(self):
        super().setUp()
        self.manager = helpers.LrpMacManager.get_instance()
        self.manager.known_routers.clear()

    def test_singleton_instance(self):
        instance2 = helpers.LrpMacManager.get_instance()
        self.assertIs(self.manager, instance2)

    def test_register_router_valid_prefix(self):
        router_name = "test-router"
        mac_prefix = "aa:bb:cc"

        self.manager.register_router(router_name, mac_prefix)

        self.assertIn(router_name, self.manager.known_routers)
        router = self.manager.known_routers[router_name]
        self.assertEqual(router.mac_prefix, mac_prefix)
        # Should have 3 remaining bytes (6 total - 3 prefix)
        self.assertEqual(router.remaining_bytes, 3)
        # Max index for 3 bytes is 255^3 - 1
        self.assertEqual(router.max_mac_index, 255 ** 3 - 1)

    def test_register_router_different_prefix_lengths(self):
        test_cases = [
            ("aa", 5, 255 ** 5 - 1),
            ("aa:bb", 4, 255 ** 4 - 1),
            ("aa:bb:cc", 3, 255 ** 3 - 1),
            ("aa:bb:cc:dd", 2, 255 ** 2 - 1),
            ("aa:bb:cc:dd:ee", 1, 255 ** 1 - 1),
        ]

        for prefix, expected_remaining, expected_max in test_cases:
            router_name = f"router-{prefix.replace(':', '')}"
            self.manager.register_router(router_name, prefix)
            router = self.manager.known_routers[router_name]
            self.assertEqual(router.remaining_bytes, expected_remaining)
            self.assertEqual(router.max_mac_index, expected_max)

    def test_get_mac_address_valid_index(self):
        router_name = "test-router"
        mac_prefix = "aa:bb:cc"
        self.manager.register_router(router_name, mac_prefix)

        mac = self.manager.get_mac_address(router_name, 1)
        self.assertEqual(mac, "aa:bb:cc:00:00:01")

        mac = self.manager.get_mac_address(router_name, 256)
        self.assertEqual(mac, "aa:bb:cc:00:01:00")

        mac = self.manager.get_mac_address(router_name, 65536)
        self.assertEqual(mac, "aa:bb:cc:01:00:00")

    def test_get_mac_address_unregistered_router(self):
        self.assertRaises(
            RuntimeError,
            self.manager.get_mac_address, "nonexistent-router", 1)

    def test_get_mac_address_index_too_large(self):
        router_name = "test-router"
        mac_prefix = "aa:bb:cc:dd:ee"  # Only 1 remaining byte
        self.manager.register_router(router_name, mac_prefix)

        # Max index for 1 byte is 255
        self.assertRaises(
            ValueError, self.manager.get_mac_address, router_name, 256)

    def test_get_mac_address_zero_index(self):
        router_name = "test-router"
        mac_prefix = "aa:bb:cc"
        self.manager.register_router(router_name, mac_prefix)

        mac = self.manager.get_mac_address(router_name, 0)
        self.assertEqual(mac, "aa:bb:cc:00:00:00")

    def test_get_mac_address_formatting(self):
        router_name = "test-router"
        mac_prefix = "aa:bb"
        self.manager.register_router(router_name, mac_prefix)

        # Test various indices to ensure proper formatting
        test_cases = [
            (1, "aa:bb:00:00:00:01"),
            (255, "aa:bb:00:00:00:ff"),
            (256, "aa:bb:00:00:01:00"),
            (65535, "aa:bb:00:00:ff:ff"),
            (65536, "aa:bb:00:01:00:00"),
        ]

        for index, expected in test_cases:
            mac = self.manager.get_mac_address(router_name, index)
            self.assertEqual(mac, expected)

    def test_mac_invalid_index(self):
        router_name = "test-router"
        mac_prefix = "aa:bb:cc"
        self.manager.register_router(router_name, mac_prefix)

        self.assertRaises(
            ValueError, self.manager.get_mac_address, router_name, -1)

    def test_too_long_mac_prefix(self):
        router_name = "test-router"
        mac_prefix = "aa:bb:cc:dd:ee:ff:gg"
        self.assertRaises(
            ValueError, self.manager.register_router, router_name, mac_prefix)

    def test_mac_prefix_without_colons(self):
        router_name = "test-router"
        mac_prefix = "aa"
        self.manager.register_router(router_name, mac_prefix)
        mac = self.manager.get_mac_address(router_name, 1)
        self.assertEqual("aa:00:00:00:00:01", mac)
