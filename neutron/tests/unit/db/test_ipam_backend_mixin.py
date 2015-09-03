# Copyright (c) 2015 Infoblox Inc.
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

import mock

from neutron.common import constants
from neutron.db import ipam_backend_mixin
from neutron.tests import base


class TestIpamBackendMixin(base.BaseTestCase):

    def setUp(self):
        super(TestIpamBackendMixin, self).setUp()
        self.mixin = ipam_backend_mixin.IpamBackendMixin()
        self.ctx = mock.Mock()
        self.default_new_ips = (('id-1', '192.168.1.1'),
                                ('id-2', '192.168.1.2'))
        self.default_original_ips = (('id-1', '192.168.1.1'),
                                     ('id-5', '172.20.16.5'))
        self.owner_non_router = constants.DEVICE_OWNER_DHCP
        self.owner_router = constants.DEVICE_OWNER_ROUTER_INTF

    def _prepare_ips(self, ips):
        return [{'ip_address': ip[1],
                 'subnet_id': ip[0]} for ip in ips]

    def _mock_slaac_subnet_on(self):
        slaac_subnet = {'ipv6_address_mode': constants.IPV6_SLAAC,
                        'ipv6_ra_mode': constants.IPV6_SLAAC}
        self.mixin._get_subnet = mock.Mock(return_value=slaac_subnet)

    def _mock_slaac_subnet_off(self):
        non_slaac_subnet = {'ipv6_address_mode': None,
                            'ipv6_ra_mode': None}
        self.mixin._get_subnet = mock.Mock(return_value=non_slaac_subnet)

    def _test_get_changed_ips_for_port(self, expected_change, original_ips,
                                       new_ips, owner):
        change = self.mixin._get_changed_ips_for_port(self.ctx,
                                                      original_ips,
                                                      new_ips,
                                                      owner)
        self.assertEqual(expected_change, change)

    def test__get_changed_ips_for_port(self):
        new_ips = self._prepare_ips(self.default_new_ips)
        original_ips = self._prepare_ips(self.default_original_ips)

        expected_change = self.mixin.Changes(add=[new_ips[1]],
                                             original=[original_ips[0]],
                                             remove=[original_ips[1]])
        self._test_get_changed_ips_for_port(expected_change, original_ips,
                                            new_ips, self.owner_router)

    def test__get_changed_ips_for_port_autoaddress(self):
        new_ips = self._prepare_ips(self.default_new_ips)

        original = (('id-1', '192.168.1.1'),
                    ('id-5', '2000:1234:5678::12FF:FE34:5678'))
        original_ips = self._prepare_ips(original)

        self._mock_slaac_subnet_on()

        expected_change = self.mixin.Changes(add=[new_ips[1]],
                                             original=original_ips,
                                             remove=[])
        self._test_get_changed_ips_for_port(expected_change, original_ips,
                                            new_ips, self.owner_non_router)

    def test__get_changed_ips_for_port_autoaddress_ipv6_pd_enabled(self):
        owner_not_router = constants.DEVICE_OWNER_DHCP
        new_ips = self._prepare_ips(self.default_new_ips)

        original = (('id-1', '192.168.1.1'),
                    ('id-5', '2000:1234:5678::12FF:FE34:5678'))
        original_ips = self._prepare_ips(original)

        # mock to test auto address part
        pd_subnet = {'subnetpool_id': constants.IPV6_PD_POOL_ID,
                     'ipv6_address_mode': constants.IPV6_SLAAC,
                     'ipv6_ra_mode': constants.IPV6_SLAAC}
        self.mixin._get_subnet = mock.Mock(return_value=pd_subnet)

        # make a copy of original_ips
        # since it is changed by _get_changed_ips_for_port
        expected_change = self.mixin.Changes(add=[new_ips[1]],
                                             original=[original_ips[0]],
                                             remove=[original_ips[1]])

        self._test_get_changed_ips_for_port(expected_change, original_ips,
                                            new_ips, owner_not_router)

    def _test_get_changed_ips_for_port_no_ip_address(self):
        # IP address should be added if only subnet_id is provided,
        # independently from auto_address status for subnet
        new_ips = [{'subnet_id': 'id-3'}]
        original_ips = []

        expected_change = self.mixin.Changes(add=[new_ips[0]],
                                             original=[],
                                             remove=[])
        self._test_get_changed_ips_for_port(expected_change, original_ips,
                                            new_ips, self.owner_non_router)

    def test__get_changed_ips_for_port_no_ip_address_no_slaac(self):
        self._mock_slaac_subnet_off()
        self._test_get_changed_ips_for_port_no_ip_address()

    def test__get_changed_ips_for_port_no_ip_address_slaac(self):
        self._mock_slaac_subnet_on()
        self._test_get_changed_ips_for_port_no_ip_address()

    def test__is_ip_required_by_subnet_for_router_port(self):
        # Owner -> router:
        # _get_subnet should not be called,
        # expected True
        self._mock_slaac_subnet_off()

        result = self.mixin._is_ip_required_by_subnet(self.ctx, 'id',
                                                      self.owner_router)
        self.assertTrue(result)
        self.assertFalse(self.mixin._get_subnet.called)

    def test__is_ip_required_by_subnet_for_non_router_port(self):
        # Owner -> not router:
        # _get_subnet should be called,
        # expected True, because subnet is not slaac
        self._mock_slaac_subnet_off()

        result = self.mixin._is_ip_required_by_subnet(self.ctx, 'id',
                                                      self.owner_non_router)
        self.assertTrue(result)
        self.assertTrue(self.mixin._get_subnet.called)

    def test__is_ip_required_by_subnet_for_non_router_port_and_slaac(self):
        # Owner -> not router:
        # _get_subnet should be called,
        # expected False, because subnet is slaac
        self._mock_slaac_subnet_on()

        result = self.mixin._is_ip_required_by_subnet(self.ctx, 'id',
                                                      self.owner_non_router)
        self.assertFalse(result)
        self.assertTrue(self.mixin._get_subnet.called)
