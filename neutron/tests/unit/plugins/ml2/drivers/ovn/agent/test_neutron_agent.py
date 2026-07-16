# Copyright 2022 Red Hat, Inc.
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

from oslo_utils import uuidutils

from neutron.common.ovn import constants as ovn_const
from neutron.plugins.ml2.drivers.ovn.agent import neutron_agent
from neutron.tests import base
from neutron.tests.unit import fake_resources as fakes


class TestNeutronAgentState(base.BaseTestCase):

    def _make_chassis_private(self, name=None, hostname='test-host',
                              gw_chassis=False, external_ids=None):
        name = name or uuidutils.generate_uuid()
        other_config = {}
        if gw_chassis:
            other_config = {'ovn-cms-options': 'enable-chassis-as-gw'}
        chassis = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'other_config': other_config,
                   'hostname': hostname,
                   'name': name})
        return fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': name,
                   'chassis': [chassis],
                   'external_ids': external_ids or {}})

    def test_controller_agent_state(self):
        ch_private = self._make_chassis_private(hostname='compute-0')
        agent = neutron_agent.ControllerAgent(ch_private)
        state = agent.agent_state()
        self.assertEqual(ovn_const.OVN_CONTROLLER_AGENT, state['agent_type'])
        self.assertEqual('ovn-controller', state['binary'])
        self.assertEqual('compute-0', state['host'])
        self.assertEqual('n/a', state['topic'])
        self.assertEqual(ch_private.name, state['id'])
        self.assertIn('chassis_name', state['configurations'])
        self.assertNotIn('alive', state)
        self.assertNotIn('start_flag', state)

    def test_gateway_agent_state(self):
        ch_private = self._make_chassis_private(
            hostname='gw-0', gw_chassis=True)
        agent = neutron_agent.ControllerAgent(ch_private)
        self.assertIsInstance(agent, neutron_agent.ControllerGatewayAgent)
        state = agent.agent_state()
        self.assertEqual(ovn_const.OVN_CONTROLLER_GW_AGENT,
                         state['agent_type'])

    def test_ovn_neutron_agent_state(self):
        ext_ids = {ovn_const.OVN_AGENT_NEUTRON_ID_KEY: 'neutron-uuid'}
        ch_private = self._make_chassis_private(
            hostname='compute-2', external_ids=ext_ids)
        agent = neutron_agent.OVNNeutronAgent(ch_private)
        state = agent.agent_state()
        self.assertEqual(ovn_const.OVN_NEUTRON_AGENT, state['agent_type'])
        self.assertEqual('neutron-ovn-agent', state['binary'])
        self.assertEqual('compute-2', state['host'])
        self.assertEqual('neutron-uuid', state['id'])

    def test_controller_agent_id_is_chassis_name(self):
        name = uuidutils.generate_uuid()
        ch_private = self._make_chassis_private(name=name)
        agent = neutron_agent.ControllerAgent(ch_private)
        self.assertEqual(name, agent.agent_id)
        self.assertEqual(name, agent.agent_state()['id'])

    def test_agent_state_has_required_keys(self):
        ch_private = self._make_chassis_private()
        agent = neutron_agent.ControllerAgent(ch_private)
        state = agent.agent_state()
        for key in ('agent_type', 'binary', 'host', 'topic', 'id',
                    'configurations'):
            self.assertIn(key, state, f'Missing key: {key}')

    def test_description_from_external_ids(self):
        ext_ids = {ovn_const.OVN_AGENT_DESC_KEY: 'my description'}
        ch_private = self._make_chassis_private(external_ids=ext_ids)
        agent = neutron_agent.ControllerAgent(ch_private)
        self.assertEqual('my description', agent.agent_state()['description'])

    def test_description_default_empty(self):
        ch_private = self._make_chassis_private()
        agent = neutron_agent.ControllerAgent(ch_private)
        self.assertEqual('', agent.agent_state()['description'])

    def test_deleted_chassis_sentinel(self):
        ch_private = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'orphan',
                   'chassis': [],
                   'external_ids': {}})
        agent = neutron_agent.ControllerAgent(ch_private)
        self.assertEqual(neutron_agent.DeletedChassis, agent.chassis)

    def test_from_type(self):
        ch_private = self._make_chassis_private()
        agent = neutron_agent.NeutronAgent.from_type(
            ovn_const.OVN_CONTROLLER_AGENT, ch_private)
        self.assertIsInstance(agent, neutron_agent.ControllerAgent)
