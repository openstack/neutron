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
from tempest.lib import decorators
import testtools

from neutron.tests.tempest.api import base
from neutron.tests.tempest import config

AZ_SUPPORTED_AGENTS = [constants.AGENT_TYPE_DHCP, constants.AGENT_TYPE_L3]
CONF = config.CONF


class AgentAvailabilityZoneTestCase(base.BaseAdminNetworkTest):

    required_extensions = ['agent', 'availability_zone']

    @classmethod
    def resource_setup(cls):
        super(AgentAvailabilityZoneTestCase, cls).resource_setup()
        body = cls.admin_client.list_agents()
        agents = body['agents']
        agents_type = [agent.get('agent_type') for agent in agents]
        for az_agent in AZ_SUPPORTED_AGENTS:
            if az_agent in agents_type:
                return
        msg = 'availability_zone supported agent not found.'
        raise cls.skipException(msg)

    @decorators.idempotent_id('3ffa661e-cfcc-417d-8b63-1c5ec4a22e54')
    @testtools.skipUnless(CONF.neutron_plugin_options.agent_availability_zone,
                          "Need a single availability_zone assumption.")
    def test_agents_availability_zone(self):
        """
        Test list agents availability_zone, only L3 and DHCP agent support
        availability_zone, default availability_zone is "nova".
        """
        body = self.admin_client.list_agents()
        agents = body['agents']
        for agent in agents:
            if agent.get('agent_type') in AZ_SUPPORTED_AGENTS:
                self.assertEqual(
                    CONF.neutron_plugin_options.agent_availability_zone,
                    agent.get('availability_zone'))
