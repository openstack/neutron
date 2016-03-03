# Copyright 2014 OpenStack Foundation
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

from tempest import test

from neutron.tests.api import base


class PortsTestJSON(base.BaseNetworkTest):

    @classmethod
    def resource_setup(cls):
        super(PortsTestJSON, cls).resource_setup()
        cls.network = cls.create_network()

    @test.attr(type='smoke')
    @test.idempotent_id('c72c1c0c-2193-4aca-bbb4-b1442640bbbb')
    def test_create_update_port_description(self):
        if not test.is_extension_enabled('standard-attr-description',
                                         'network'):
            msg = "standard-attr-description not enabled."
            raise self.skipException(msg)
        body = self.create_port(self.network,
                                description='d1')
        self.assertEqual('d1', body['description'])
        body = self.client.list_ports(id=body['id'])['ports'][0]
        self.assertEqual('d1', body['description'])
        body = self.client.update_port(body['id'],
                                       description='d2')
        self.assertEqual('d2', body['port']['description'])
        body = self.client.list_ports(id=body['port']['id'])['ports'][0]
        self.assertEqual('d2', body['description'])
