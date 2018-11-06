# Copyright 2018 Ericsson
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

from neutron_lib import constants

from neutron.common import constants as c_const
from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import config as f_const
from neutron.tests.fullstack.resources import environment
from neutron.tests.unit import testlib_api

load_tests = testlib_api.module_load_tests


class TestAgentBandwidthReport(base.BaseFullStackTestCase):

    scenarios = [
        (constants.AGENT_TYPE_OVS,
         {'l2_agent_type': constants.AGENT_TYPE_OVS}),
        (constants.AGENT_TYPE_NIC_SWITCH,
         {'l2_agent_type': constants.AGENT_TYPE_NIC_SWITCH})
    ]

    def setUp(self):
        host_desc = [environment.HostDescription(
            l3_agent=False,
            l2_agent_type=self.l2_agent_type)]
        env_desc = environment.EnvironmentDescription(
            network_type='vlan',
            l2_pop=False,
            report_bandwidths=True
        )
        env = environment.Environment(env_desc, host_desc)

        super(TestAgentBandwidthReport, self).setUp(env)

    def test_agent_configurations(self):
        agents = self.client.list_agents()

        self.assertEqual(1, len(agents['agents']))

        agent_configurations = agents['agents'][0]['configurations']
        if 'bridge_mappings' in agent_configurations:
            mapping_key = 'bridge_mappings'
        elif 'device_mappings' in agent_configurations:
            mapping_key = 'device_mappings'
        else:
            self.fail('No mapping information is found in agent '
                      'configurations')

        physnet = list(agent_configurations[mapping_key])[0]
        bridge_or_devices = agent_configurations[mapping_key][physnet]

        self.assertIn(c_const.RP_BANDWIDTHS, agent_configurations)
        self.assertIn(c_const.RP_INVENTORY_DEFAULTS, agent_configurations)
        if mapping_key == 'bridge_mappings':
            self.assertIn(bridge_or_devices,
                          agent_configurations[c_const.RP_BANDWIDTHS])
        else:
            for device in bridge_or_devices:
                self.assertIn(device, agent_configurations[
                    c_const.RP_BANDWIDTHS])

        for device in agent_configurations[c_const.RP_BANDWIDTHS]:
            self.assertEqual(
                f_const.MINIMUM_BANDWIDTH_INGRESS_KBPS,
                agent_configurations[c_const.RP_BANDWIDTHS][device]['ingress'])
            self.assertEqual(
                f_const.MINIMUM_BANDWIDTH_EGRESS_KBPS,
                agent_configurations[c_const.RP_BANDWIDTHS][device]['egress'])
