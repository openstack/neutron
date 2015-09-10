# Copyright 2015 Red Hat, Inc.
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

import testscenarios

from oslo_utils import uuidutils

from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import environment
from neutron.tests.fullstack.resources import machine


load_tests = testscenarios.load_tests_apply_scenarios


class TestConnectivitySameNetwork(base.BaseFullStackTestCase):

    scenarios = [('VXLAN', {'network_type': 'vxlan'}),
                 ('VLANs', {'network_type': 'vlan'})]

    def setUp(self):
        host_descriptions = [
            environment.HostDescription() for _ in range(2)]
        env = environment.Environment(
            environment.EnvironmentDescription(
                network_type=self.network_type),
            host_descriptions)
        super(TestConnectivitySameNetwork, self).setUp(env)

    def test_connectivity(self):
        tenant_uuid = uuidutils.generate_uuid()

        network = self.safe_client.create_network(tenant_uuid)
        self.safe_client.create_subnet(
            tenant_uuid, network['id'], '20.0.0.0/24')

        vms = [
            self.useFixture(
                machine.FakeFullstackMachine(
                    self.environment.hosts[i],
                    network['id'],
                    tenant_uuid,
                    self.safe_client))
            for i in range(2)]

        for vm in vms:
            vm.block_until_boot()

        vms[0].assert_ping(vms[1].ip)
