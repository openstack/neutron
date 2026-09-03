# Copyright 2026 Red Hat, LLC
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

from neutron_lib import constants
from oslo_utils import uuidutils

from neutron.objects import bgp as bgp_objects
from neutron.objects import subnet as subnet_obj
from neutron.tests.unit.objects import test_base as obj_test_base
from neutron.tests.unit import testlib_api


class SubnetBGPLeakRoutesDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                                          testlib_api.SqlTestCase):

    _test_class = bgp_objects.SubnetBGPLeakRoutes

    def setUp(self):
        super().setUp()
        self.update_obj_fields(
            {'subnet_id': lambda: self._create_test_subnet_id()})

    def _create_subnet_with_cidr(self, cidr, network_id=None):
        if not network_id:
            network_id = self._create_test_network_id()
        gateway = str(netaddr.IPNetwork(cidr).network + 1)
        ip_version = (constants.IP_VERSION_6
                      if netaddr.IPNetwork(cidr).version == 6
                      else constants.IP_VERSION_4)
        sub = subnet_obj.Subnet(
            self.context,
            project_id=uuidutils.generate_uuid(),
            name='test-subnet',
            network_id=network_id,
            ip_version=ip_version,
            cidr=netaddr.IPNetwork(cidr),
            gateway_ip=gateway,
            enable_dhcp=True,
            ipv6_ra_mode=None,
            ipv6_address_mode=None)
        sub.create()
        return sub

    def test_get_leaked_subnet_cidrs_empty(self):
        result = bgp_objects.SubnetBGPLeakRoutes.get_leaked_subnet_cidrs(
            self.context)
        self.assertEqual([], result)

    def test_get_leaked_subnet_cidrs_returns_leaked_only(self):
        leaked_sub = self._create_subnet_with_cidr('10.0.0.0/24')
        self._create_subnet_with_cidr('10.0.1.0/24')

        bgp_objects.SubnetBGPLeakRoutes(
            self.context, subnet_id=leaked_sub.id).create()

        result = bgp_objects.SubnetBGPLeakRoutes.get_leaked_subnet_cidrs(
            self.context)
        self.assertEqual(1, len(result))
        self.assertEqual(leaked_sub.id, result[0][0])
        self.assertEqual('10.0.0.0/24', result[0][1])

    def test_get_leaked_subnet_cidrs_multiple(self):
        sub1 = self._create_subnet_with_cidr('10.0.0.0/24')
        sub2 = self._create_subnet_with_cidr('fd00::/64')

        bgp_objects.SubnetBGPLeakRoutes(
            self.context, subnet_id=sub1.id).create()
        bgp_objects.SubnetBGPLeakRoutes(
            self.context, subnet_id=sub2.id).create()

        result = bgp_objects.SubnetBGPLeakRoutes.get_leaked_subnet_cidrs(
            self.context)
        self.assertEqual(2, len(result))
        result_map = {row[0]: row[1] for row in result}
        self.assertEqual('10.0.0.0/24', result_map[sub1.id])
        self.assertEqual('fd00::/64', result_map[sub2.id])

    def test_get_leaked_subnet_cidrs_deleted_entry_not_returned(self):
        sub = self._create_subnet_with_cidr('192.168.0.0/16')
        leak = bgp_objects.SubnetBGPLeakRoutes(
            self.context, subnet_id=sub.id)
        leak.create()

        bgp_objects.SubnetBGPLeakRoutes.delete_objects(
            self.context, subnet_id=sub.id)

        result = bgp_objects.SubnetBGPLeakRoutes.get_leaked_subnet_cidrs(
            self.context)
        self.assertEqual([], result)

    def test_network_has_leaked_subnets_false_when_empty(self):
        network_id = self._create_test_network_id()
        self.assertFalse(
            bgp_objects.SubnetBGPLeakRoutes.network_has_leaked_subnets(
                self.context, network_id))

    def test_network_has_leaked_subnets_true(self):
        network_id = self._create_test_network_id()
        sub = self._create_subnet_with_cidr('10.0.0.0/24',
                                            network_id=network_id)
        bgp_objects.SubnetBGPLeakRoutes(
            self.context, subnet_id=sub.id).create()

        self.assertTrue(
            bgp_objects.SubnetBGPLeakRoutes.network_has_leaked_subnets(
                self.context, network_id))

    def test_network_has_leaked_subnets_false_different_network(self):
        network_a = self._create_test_network_id()
        network_b = self._create_test_network_id()
        sub = self._create_subnet_with_cidr('10.0.0.0/24',
                                            network_id=network_a)
        bgp_objects.SubnetBGPLeakRoutes(
            self.context, subnet_id=sub.id).create()

        self.assertFalse(
            bgp_objects.SubnetBGPLeakRoutes.network_has_leaked_subnets(
                self.context, network_b))
