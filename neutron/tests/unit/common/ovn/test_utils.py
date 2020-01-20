# Copyright 2018 Red Hat, Inc.
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

import fixtures

from neutron.common.ovn import constants
from neutron.common.ovn import utils
from neutron.tests import base
from neutron.tests.unit import fake_resources as fakes

RESOLV_CONF_TEMPLATE = """# TEST TEST TEST
# Geneated by OVN test
nameserver 10.0.0.1
#nameserver 10.0.0.2
nameserver 10.0.0.3
nameserver foo 10.0.0.4
nameserver aef0::4
foo 10.0.0.5
"""


class TestUtils(base.BaseTestCase):

    def test_get_system_dns_resolvers(self):
        tempdir = self.useFixture(fixtures.TempDir()).path
        resolver_file_name = tempdir + '/resolv.conf'
        tmp_resolv_file = open(resolver_file_name, 'w')
        tmp_resolv_file.writelines(RESOLV_CONF_TEMPLATE)
        tmp_resolv_file.close()
        expected_dns_resolvers = ['10.0.0.1', '10.0.0.3']
        observed_dns_resolvers = utils.get_system_dns_resolvers(
            resolver_file=resolver_file_name)
        self.assertEqual(expected_dns_resolvers, observed_dns_resolvers)

    def test_is_gateway_chassis(self):
        chassis = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'external_ids': {'ovn-cms-options': 'enable-chassis-as-gw'}})
        non_gw_chassis_0 = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'external_ids': {'ovn-cms-options': ''}})
        non_gw_chassis_1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={})
        non_gw_chassis_2 = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'external_ids': {}})

        self.assertTrue(utils.is_gateway_chassis(chassis))
        self.assertFalse(utils.is_gateway_chassis(non_gw_chassis_0))
        self.assertFalse(utils.is_gateway_chassis(non_gw_chassis_1))
        self.assertFalse(utils.is_gateway_chassis(non_gw_chassis_2))


class TestGateWayChassisValidity(base.BaseTestCase):

    def setUp(self):
        super(TestGateWayChassisValidity, self).setUp()
        self.gw_chassis = ['host1', 'host2']
        self.chassis_name = self.gw_chassis[0]
        self.physnet = 'physical-nw-1'
        self.chassis_physnets = {self.chassis_name: [self.physnet]}

    def test_gateway_chassis_valid(self):
        # Return False, since everything is valid
        self.assertFalse(utils.is_gateway_chassis_invalid(
            self.chassis_name, self.gw_chassis, self.physnet,
            self.chassis_physnets))

    def test_gateway_chassis_due_to_invalid_chassis_name(self):
        # Return True since chassis is invalid
        self.chassis_name = constants.OVN_GATEWAY_INVALID_CHASSIS
        self.assertTrue(utils.is_gateway_chassis_invalid(
            self.chassis_name, self.gw_chassis, self.physnet,
            self.chassis_physnets))

    def test_gateway_chassis_for_chassis_not_in_chassis_physnets(self):
        # Return True since chassis is not in chassis_physnets
        self.chassis_name = 'host-2'
        self.assertTrue(utils.is_gateway_chassis_invalid(
            self.chassis_name, self.gw_chassis, self.physnet,
            self.chassis_physnets))

    def test_gateway_chassis_for_undefined_physnet(self):
        # Return True since physnet is not defined
        self.chassis_name = 'host-1'
        self.physnet = None
        self.assertTrue(utils.is_gateway_chassis_invalid(
            self.chassis_name, self.gw_chassis, self.physnet,
            self.chassis_physnets))

    def test_gateway_chassis_for_physnet_not_in_chassis_physnets(self):
        # Return True since physnet is not in chassis_physnets
        self.physnet = 'physical-nw-2'
        self.assertTrue(utils.is_gateway_chassis_invalid(
            self.chassis_name, self.gw_chassis, self.physnet,
            self.chassis_physnets))

    def test_gateway_chassis_for_gw_chassis_empty(self):
        # Return False if gw_chassis is []
        # This condition states that the chassis is valid, has valid
        # physnets and there are no gw_chassis present in the system.
        self.gw_chassis = []
        self.assertFalse(utils.is_gateway_chassis_invalid(
            self.chassis_name, self.gw_chassis, self.physnet,
            self.chassis_physnets))

    def test_gateway_chassis_for_chassis_not_in_gw_chassis_list(self):
        # Return True since chassis_name not in gw_chassis
        self.gw_chassis = ['host-2']
        self.assertTrue(utils.is_gateway_chassis_invalid(
            self.chassis_name, self.gw_chassis, self.physnet,
            self.chassis_physnets))
