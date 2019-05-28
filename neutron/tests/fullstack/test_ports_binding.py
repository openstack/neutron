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

from neutron_lib.api.definitions import portbindings
from neutron_lib import constants
from oslo_utils import uuidutils

from neutron.common import utils as common_utils
from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import environment
from neutron.tests.unit import testlib_api

load_tests = testlib_api.module_load_tests


class TestPortsBinding(base.BaseFullStackTestCase):
    scenarios = [
        ('Open vSwitch Agent', {'l2_agent_type': constants.AGENT_TYPE_OVS})]

    def setUp(self):
        host_descriptions = [
            environment.HostDescription(
                l2_agent_type=self.l2_agent_type,
                l3_agent=False)]
        env = environment.Environment(
            environment.EnvironmentDescription(
                agent_down_time=10),
            host_descriptions)

        super(TestPortsBinding, self).setUp(env)

        self.l2_agent_process = self.environment.hosts[0].l2_agent
        self.l2_agent = self.safe_client.client.list_agents(
            agent_type=self.l2_agent_type)['agents'][0]

        self.tenant_id = uuidutils.generate_uuid()
        self.network = self.safe_client.create_network(self.tenant_id)
        self.subnet = self.safe_client.create_subnet(
            self.tenant_id, self.network['id'], '20.0.0.0/24')

    def _ensure_port_bound(self, port_id):
        def port_bound():
            port = self.safe_client.client.show_port(port_id)['port']
            return (port[portbindings.VIF_TYPE] not in
                    [portbindings.VIF_TYPE_UNBOUND,
                     portbindings.VIF_TYPE_BINDING_FAILED])

        common_utils.wait_until_true(port_bound)

    def _ensure_port_binding_failed(self, port_id):
        def port_binding_failed():
            port = self.safe_client.client.show_port(port_id)['port']
            return (port[portbindings.VIF_TYPE] ==
                    portbindings.VIF_TYPE_BINDING_FAILED)

        common_utils.wait_until_true(port_binding_failed)

    def test_smartnic_port_binding(self):
        """Test scenario

        1. Create SmartNIC port which will not be properly bound to host
        because OVS agent doesn't bind SmartNIC ports by default
        2. Validate port's bound status to be bound failed
        3. Stop L2 agent and wait until it will be DEAD
        4. Set `baremetal_smartnic=True` in agent config
        5. Start L2 agent and wait until it is Alive
        6. Create SmartNIC port which will be properly bound to host
        7. Validate port's bound status
        """

        smartnic_port = self.safe_client.create_port(
            self.tenant_id,
            self.network['id'],
            self.environment.hosts[0].hostname,
            **{"binding:vnic_type": "smart-nic",
               "binding:profile": {
                   "local_link_information": [
                       {
                           "port_id": "port1",
                           "hostname": self.environment.hosts[0].hostname,
                       }
                   ]
               }
               }
        )

        self._ensure_port_binding_failed(smartnic_port['id'])

        # configure neutron agent to bind SmartNIC ports
        self.l2_agent_process = self.environment.hosts[0].l2_agent
        self.l2_agent = self.safe_client.client.list_agents(
            agent_type=self.l2_agent_type)['agents'][0]
        self.l2_agent_process.stop()
        self._wait_until_agent_down(self.l2_agent['id'])
        l2_agent_config = self.l2_agent_process.agent_cfg_fixture.config
        l2_agent_config['agent']['baremetal_smartnic'] = 'True'
        self.l2_agent_process.agent_cfg_fixture.write_config_to_configfile()
        self.l2_agent_process.restart()
        self._wait_until_agent_up(self.l2_agent['id'])

        self._ensure_port_bound(smartnic_port['id'])
