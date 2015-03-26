# Copyright 2015 OpenStack Foundation
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

from tempest_lib.common.utils import data_utils
from tempest_lib import exceptions as lib_exc

from neutron.tests.api import base_security_groups as base
from neutron.tests.tempest import config
from neutron.tests.tempest import test


CONF = config.CONF
FAKE_IP = '10.0.0.1'
FAKE_MAC = '00:25:64:e8:19:dd'


class PortSecTest(base.BaseSecGroupTest):

    @classmethod
    def resource_setup(cls):
        super(PortSecTest, cls).resource_setup()

    def _create_network(self, network_name=None, port_security_enabled=True):
        """Wrapper utility that returns a test network."""
        network_name = network_name or data_utils.rand_name('test-network')

        body = self.client.create_network(
            name=network_name, port_security_enabled=port_security_enabled)
        network = body['network']
        self.networks.append(network)
        return network

    @test.attr(type='smoke')
    @test.idempotent_id('7c338ddf-e64e-4118-bd33-e49a1f2f1495')
    @test.requires_ext(extension='port-security', service='network')
    def test_port_sec_default_value(self):
        # Default port-sec value is True, and the attr of the port will inherit
        # from the port-sec of the network when it not be specified in API
        network = self.create_network()
        self.create_subnet(network)
        self.assertTrue(network['port_security_enabled'])
        port = self.create_port(network)
        self.assertTrue(port['port_security_enabled'])

    @test.attr(type='smoke')
    @test.idempotent_id('e60eafd2-31de-4c38-8106-55447d033b57')
    @test.requires_ext(extension='port-security', service='network')
    def test_port_sec_specific_value(self):
        network = self.create_network()

        self.assertTrue(network['port_security_enabled'])
        self.create_subnet(network)
        port = self.create_port(network, port_security_enabled=False)
        self.assertFalse(port['port_security_enabled'])

        # Create a network with port-sec set to False
        network = self._create_network(port_security_enabled=False)

        self.assertFalse(network['port_security_enabled'])
        self.create_subnet(network)
        port = self.create_port(network, port_security_enabled=True)
        self.assertTrue(port['port_security_enabled'])

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('05642059-1bfc-4581-9bc9-aaa5db08dd60')
    @test.requires_ext(extension='port-security', service='network')
    def test_port_sec_update_port_failed(self):
        network = self.create_network()
        self.create_subnet(network)
        port = self.create_port(network)

        # Exception when set port-sec to False with sec-group defined
        self.assertRaises(lib_exc.Conflict,
                          self.update_port, port, port_security_enabled=False)

        updated_port = self.update_port(
            port, security_groups=[], port_security_enabled=False)
        self.assertFalse(updated_port['port_security_enabled'])

        allowed_address_pairs = [{'ip_address': FAKE_IP,
                                  'mac_address': FAKE_MAC}]

        # Exception when set address-pairs with port-sec is False
        self.assertRaises(lib_exc.Conflict,
                          self.update_port, port,
                          allowed_address_pairs=allowed_address_pairs)
