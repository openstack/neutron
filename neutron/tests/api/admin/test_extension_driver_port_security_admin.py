# Copyright 2015 Cisco Systems, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
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

from neutron.tests.api import base
from neutron.tests.api import base_security_groups as base_security
from neutron.tests.tempest import test
from tempest_lib import exceptions as lib_exc


class PortSecurityAdminTests(base_security.BaseSecGroupTest,
                             base.BaseAdminNetworkTest):

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('d39a96e2-2dea-4feb-8093-e7ac991ce6f8')
    def test_create_port_security_false_on_shared_network(self):
        network = self.create_shared_network()
        self.assertTrue(network['shared'])
        self.create_subnet(network, client=self.admin_client)
        self.assertRaises(lib_exc.Forbidden, self.create_port,
                          network, port_security_enabled=False)
