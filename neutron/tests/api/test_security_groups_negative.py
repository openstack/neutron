# Copyright 2013 OpenStack Foundation
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

from tempest.lib import exceptions as lib_exc
from tempest import test

from neutron.tests.api import base_security_groups as base
from neutron.tests.tempest import config

CONF = config.CONF


class NegativeSecGroupTest(base.BaseSecGroupTest):

    @classmethod
    def resource_setup(cls):
        super(NegativeSecGroupTest, cls).resource_setup()
        if not test.is_extension_enabled('security-group', 'network'):
            msg = "security-group extension not enabled."
            raise cls.skipException(msg)

    @test.attr(type=['negative', 'gate'])
    @test.idempotent_id('0d9c7791-f2ad-4e2f-ac73-abf2373b0d2d')
    def test_create_security_group_rule_with_invalid_ports(self):
        group_create_body, _ = self._create_security_group()

        # Create rule for tcp protocol with invalid ports
        states = [(-16, 80, 'Invalid value for port -16'),
                  (80, 79, 'port_range_min must be <= port_range_max'),
                  (80, 65536, 'Invalid value for port 65536'),
                  (None, 6, 'port_range_min must be <= port_range_max'),
                  (-16, 65536, 'Invalid value for port')]
        for pmin, pmax, msg in states:
            ex = self.assertRaises(
                lib_exc.BadRequest, self.client.create_security_group_rule,
                security_group_id=group_create_body['security_group']['id'],
                protocol='tcp', port_range_min=pmin, port_range_max=pmax,
                direction='ingress', ethertype=self.ethertype)
            self.assertIn(msg, str(ex))

        # Create rule for icmp protocol with invalid ports
        states = [(1, 256, 'Invalid value for ICMP code'),
                  (-1, 25, 'Invalid value'),
                  (None, 6, 'ICMP type (port-range-min) is missing'),
                  (300, 1, 'Invalid value for ICMP type')]
        for pmin, pmax, msg in states:
            ex = self.assertRaises(
                lib_exc.BadRequest, self.client.create_security_group_rule,
                security_group_id=group_create_body['security_group']['id'],
                protocol='icmp', port_range_min=pmin, port_range_max=pmax,
                direction='ingress', ethertype=self.ethertype)
            self.assertIn(msg, str(ex))

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('55100aa8-b24f-333c-0bef-64eefd85f15c')
    def test_update_default_security_group_name(self):
        sg_list = self.client.list_security_groups(name='default')
        sg = sg_list['security_groups'][0]
        self.assertRaises(lib_exc.Conflict, self.client.update_security_group,
                          sg['id'], name='test')


class NegativeSecGroupIPv6Test(NegativeSecGroupTest):
    _ip_version = 6
