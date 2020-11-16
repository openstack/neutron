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

from neutron_lib import constants
from oslo_utils import uuidutils

from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import environment
from neutron.tests.unit import testlib_api

load_tests = testlib_api.module_load_tests


class TestPortsApi(base.BaseFullStackTestCase):

    scenarios = [
        ('Sriov Agent', {'l2_agent_type': constants.AGENT_TYPE_NIC_SWITCH})]

    def setUp(self):
        host_descriptions = [
            environment.HostDescription(
                l2_agent_type=self.l2_agent_type)]
        env = environment.Environment(
            environment.EnvironmentDescription(
                agent_down_time=10,
                ml2_extension_drivers=['uplink_status_propagation']),
            host_descriptions)
        super(TestPortsApi, self).setUp(env)

        self.tenant_id = uuidutils.generate_uuid()
        self.network = self.safe_client.create_network(self.tenant_id)
        self.safe_client.create_subnet(
            self.tenant_id, self.network['id'], '20.0.0.0/24')

    def test_create_port_with_propagate_uplink_status(self):
        body = self.safe_client.create_port(
            self.tenant_id, self.network['id'], propagate_uplink_status=False)
        self.assertFalse(body['propagate_uplink_status'])
        body = self.safe_client.client.list_ports(id=body['id'])['ports'][0]
        self.assertFalse(body['propagate_uplink_status'])
        body = self.safe_client.client.show_port(body['id'])['port']
        self.assertFalse(body['propagate_uplink_status'])

    def test_create_port_without_propagate_uplink_status(self):
        body = self.safe_client.create_port(self.tenant_id, self.network['id'])
        self.assertFalse(body['propagate_uplink_status'])
        body = self.safe_client.client.list_ports(id=body['id'])['ports'][0]
        self.assertFalse(body['propagate_uplink_status'])
        body = self.safe_client.client.show_port(body['id'])['port']
        self.assertFalse(body['propagate_uplink_status'])
