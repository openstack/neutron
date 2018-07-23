# Copyright 2017 NEC India
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

# from neutronclient.common import exceptions
from oslo_utils import uuidutils

from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import environment
from neutron.tests.unit import testlib_api

load_tests = testlib_api.module_load_tests


class MTUNetworkTestSetup(base.BaseFullStackTestCase):
    host_desc = []  # No need to register agents for this test case

    def setUp(self):
        env = environment.Environment(
            environment.EnvironmentDescription(),
            self.host_desc)
        super(MTUNetworkTestSetup, self).setUp(env)

        self.tenant_id = uuidutils.generate_uuid()

    def _restart_neutron_server(self, global_mtu):
        env = environment.Environment(
            environment.EnvironmentDescription(global_mtu=global_mtu),
            self.host_desc)
        env.test_name = self.get_name()
        self.useFixture(env)
        env.neutron_server.restart()


class TestMTUScenarios(MTUNetworkTestSetup):

    def test_mtu_update_delete_network(self):
        network = self.safe_client.create_network(self.tenant_id,
                                                  name='mtu-test-network',
                                                  mtu=1450)
        self.safe_client.update_network(network['id'], mtu=9000)
        res = self.safe_client.delete_network(network['id'])
        self.assertEqual((), res)

    def test_global_physnet_mtu_update_delete_network(self):
        network = self.safe_client.create_network(self.tenant_id,
                                                  name='mtu-test-network',
                                                  mtu=1450)
        self._restart_neutron_server(1400)
        res = self.safe_client.delete_network(network['id'])
        self.assertEqual((), res)
