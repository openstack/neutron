# Copyright 2019 Ericsson
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from unittest import mock

from keystoneauth1 import exceptions as ks_exc
from neutron_lib.agent import constants as agent_const
from oslo_log import log as logging

from neutron.services.placement_report import plugin
from neutron.tests.unit.plugins.ml2.drivers import mechanism_test
from neutron.tests.unit.plugins.ml2 import test_plugin

LOG = logging.getLogger(__name__)


class PlacementReportPluginTestCases(test_plugin.Ml2PluginV2TestCase):

    _mechanism_drivers = ['logger', 'test_with_agent']

    def setUp(self):
        super(PlacementReportPluginTestCases, self).setUp()
        self.service_plugin = plugin.PlacementReportPlugin()

    def test__get_rp_by_name_found(self):
        with mock.patch.object(
                self.service_plugin._placement_client,
                'list_resource_providers',
                return_value={'resource_providers': ['fake_rp']}):
            rp = self.service_plugin._get_rp_by_name('whatever')
        self.assertEqual('fake_rp', rp)

    def test__get_rp_by_name_not_found(self):
        with mock.patch.object(
                self.service_plugin._placement_client,
                'list_resource_providers',
                return_value={'resource_providers': []}):
            self.assertRaises(
                IndexError, self.service_plugin._get_rp_by_name, 'no_such_rp')

    def test_no_sync_for_rp_name_not_found(self):
        # looking all good
        agent = {
            'agent_type': 'test_mechanism_driver_agent',
            'configurations': {
                'resource_provider_bandwidths': {'some iface': ''},
            },
            'host': 'fake host',
        }
        agent_db = mock.Mock()

        with mock.patch.object(
                self.service_plugin._placement_client,
                'list_resource_providers',
                return_value={'resource_providers': []}), \
            mock.patch.object(
                self.service_plugin._batch_notifier,
                'queue_event') as mock_queue_event:

            self.service_plugin._sync_placement_state(agent, agent_db)

            self.assertFalse(agent_db.resources_synced)
            agent_db.update.assert_called_with()
            mock_queue_event.assert_not_called()

    def test_no_sync_for_placement_gone(self):
        # looking all good
        agent = {
            'agent_type': 'test_mechanism_driver_agent',
            'configurations': {
                'resource_provider_bandwidths': {'some iface': ''}},
            'host': 'fake host',
        }
        agent_db = mock.Mock()

        with mock.patch.object(
                self.service_plugin._placement_client,
                'list_resource_providers',
                side_effect=ks_exc.HttpError), \
            mock.patch.object(
                self.service_plugin._batch_notifier,
                'queue_event') as mock_queue_event:

            self.service_plugin._sync_placement_state(agent, agent_db)

            self.assertFalse(agent_db.resources_synced)
            agent_db.update.assert_called_with()
            mock_queue_event.assert_not_called()

    def test_no_sync_for_unsupported_agent_type(self):
        payload = mock.Mock(
            # looking all good, but agent type not supported
            desired_state={
                'agent_type': 'unsupported agent type',
                'configurations': {'resource_provider_bandwidths': {}},
                'host': 'fake host',
            })

        with mock.patch.object(self.service_plugin._core_plugin,
                '_get_agent_by_type_and_host') as mock_get_agent, \
            mock.patch.object(self.service_plugin,
                '_sync_placement_state') as mock_sync:

            self.service_plugin.handle_placement_config(
                mock.ANY, mock.ANY, mock.ANY, payload)

            mock_get_agent.assert_not_called()
            mock_sync.assert_not_called()

    def test_no_sync_without_resource_info(self):
        payload = mock.Mock(
            # looking all good, but 'configurations' has no
            # 'resource_provider_bandwidths'
            desired_state={
                'agent_type': 'test_mechanism_driver_agent',
                'configurations': {},
                'host': 'fake host',
            })

        with mock.patch.object(self.service_plugin._core_plugin,
                '_get_agent_by_type_and_host') as mock_get_agent, \
            mock.patch.object(self.service_plugin,
                '_sync_placement_state') as mock_sync:

            self.service_plugin.handle_placement_config(
                mock.ANY, mock.ANY, mock.ANY, payload)

            mock_get_agent.assert_not_called()
            mock_sync.assert_not_called()

    def test_sync_if_agent_is_new(self):
        payload = mock.Mock(
            desired_state={
                'agent_type': 'test_mechanism_driver_agent',
                'configurations': {'resource_provider_bandwidths': {}},
                'host': 'fake host',
            },
            metadata={
                'status': agent_const.AGENT_NEW,
            },
        )

        with mock.patch.object(self.service_plugin._core_plugin,
                '_get_agent_by_type_and_host') as mock_get_agent, \
            mock.patch.object(self.service_plugin,
                '_sync_placement_state') as mock_sync:

            self.service_plugin.handle_placement_config(
                mock.ANY, mock.ANY, mock.ANY, payload)

            self.assertEqual(1, mock_get_agent.call_count)
            self.assertEqual(1, mock_sync.call_count)

    def test_sync_if_agent_is_restarted(self):
        payload = mock.Mock(
            desired_state={
                'agent_type': 'test_mechanism_driver_agent',
                'configurations': {'resource_provider_bandwidths': {}},
                'host': 'fake host',
                'start_flag': True,
            },
        )

        with mock.patch.object(self.service_plugin._core_plugin,
                '_get_agent_by_type_and_host') as mock_get_agent, \
            mock.patch.object(self.service_plugin,
                '_sync_placement_state') as mock_sync:

            self.service_plugin.handle_placement_config(
                mock.ANY, mock.ANY, mock.ANY, payload)

            self.assertEqual(1, mock_get_agent.call_count)
            self.assertEqual(1, mock_sync.call_count)

    def test_sync_after_transient_error(self):
        payload = mock.Mock(
            desired_state={
                'agent_type': 'test_mechanism_driver_agent',
                'configurations': {'resource_provider_bandwidths': {}},
                'host': 'fake host',
            },
        )

        with mock.patch.object(self.service_plugin._core_plugin,
                '_get_agent_by_type_and_host',
                return_value={'resources_synced': False}) as mock_get_agent, \
            mock.patch.object(self.service_plugin,
                '_sync_placement_state') as mock_sync:

            self.service_plugin.handle_placement_config(
                mock.ANY, mock.ANY, mock.ANY, payload)

            self.assertEqual(1, mock_get_agent.call_count)
            self.assertEqual(1, mock_sync.call_count)

    def test__sync_placement_state_legacy(self):
        agent = {
            'agent_type': 'test_mechanism_driver_agent',
            'configurations': {
                'resource_provider_bandwidths': {},
                'resource_provider_inventory_defaults': {},
            },
            'host': 'fake host',
        }
        agent_db = mock.Mock()

        with mock.patch.object(self.service_plugin._batch_notifier,
                'queue_event') as mock_queue_event, \
            mock.patch.object(self.service_plugin._placement_client,
               'list_resource_providers',
               return_value={'resource_providers': [{'uuid': 'fake uuid'}]}):

            self.service_plugin._sync_placement_state(agent, agent_db)

            self.assertEqual(1, mock_queue_event.call_count)

    def test__sync_placement_state_rp_hypervisors(self):
        agent = {
            'agent_type': 'test_mechanism_driver_agent',
            'configurations': {
                'resource_provider_bandwidths': {},
                'resource_provider_inventory_defaults': {},
                'resource_provider_hypervisors': {'eth0': 'hypervisor0'},
            },
            'host': 'fake host',
        }
        agent_db = mock.Mock()

        with mock.patch.object(self.service_plugin._batch_notifier,
                'queue_event') as mock_queue_event, \
            mock.patch.object(self.service_plugin._placement_client,
               'list_resource_providers',
               return_value={'resource_providers': [
                   {'uuid': 'fake uuid'}]}) as mock_list_rps:

            self.service_plugin._sync_placement_state(agent, agent_db)

            self.assertEqual(1, mock_queue_event.call_count)
            mock_list_rps.assert_called_once_with(name='hypervisor0')

    def test__sync_placement_state_rp_pkt_processing_with_direction(self):
        agent = {
            'agent_type': 'test_mechanism_driver_agent',
            'configurations': {
                'resource_provider_bandwidths': {},
                'resource_provider_inventory_defaults': {},
                'resource_provider_packet_processing_with_direction': {
                    'fake host': {'egress': 1, 'ingress': 2}
                },
                'resource_provider_packet_processing_inventory_defaults': {
                    'allocation_ratio': 1, 'min_unit': 1, 'step_size': 1
                },
            },
            'host': 'fake host',
        }
        agent_db = mock.Mock()
        mock_state = mock.Mock(return_value=[])

        with mock.patch.object(self.service_plugin._batch_notifier,
                'queue_event') as mock_queue_event, \
            mock.patch('neutron.agent.common.placement_report.PlacementState',
                return_value=mock_state) as mock_placement_state:

            self.service_plugin._sync_placement_state(agent, agent_db)

            self.assertEqual(1, mock_queue_event.call_count)
            mock_placement_state.assert_called_once_with(
                rp_pkt_processing={'fake host': {'egress': 1, 'ingress': 2}},
                rp_pkt_processing_inventory_defaults={
                    'allocation_ratio': 1, 'min_unit': 1, 'step_size': 1},
                rp_bandwidths=mock.ANY,
                rp_inventory_defaults=mock.ANY,
                driver_uuid_namespace=mock.ANY,
                agent_type=mock.ANY,
                hypervisor_rps=mock.ANY,
                device_mappings=mock.ANY,
                supported_vnic_types=mock.ANY,
                client=mock.ANY)
            mock_state.deferred_sync.assert_called_once()

    def test__sync_placement_state_rp_pkt_processing_without_direction(self):
        agent = {
            'agent_type': 'test_mechanism_driver_agent',
            'configurations': {
                'resource_provider_bandwidths': {},
                'resource_provider_inventory_defaults': {},
                'resource_provider_packet_processing_without_direction': {
                    'fake host': {'any': 1}
                },
                'resource_provider_packet_processing_inventory_defaults': {
                    'allocation_ratio': 1, 'min_unit': 1, 'step_size': 1
                },
            },
            'host': 'fake host',
        }
        agent_db = mock.Mock()
        mock_state = mock.Mock(return_value=[])

        with mock.patch.object(self.service_plugin._batch_notifier,
                'queue_event') as mock_queue_event, \
            mock.patch('neutron.agent.common.placement_report.PlacementState',
                return_value=mock_state) as mock_placement_state:

            self.service_plugin._sync_placement_state(agent, agent_db)

            self.assertEqual(1, mock_queue_event.call_count)
            mock_placement_state.assert_called_once_with(
                rp_pkt_processing={'fake host': {'any': 1}},
                rp_pkt_processing_inventory_defaults={
                    'allocation_ratio': 1, 'min_unit': 1, 'step_size': 1},
                rp_bandwidths=mock.ANY,
                rp_inventory_defaults=mock.ANY,
                driver_uuid_namespace=mock.ANY,
                agent_type=mock.ANY,
                hypervisor_rps=mock.ANY,
                device_mappings=mock.ANY,
                supported_vnic_types=mock.ANY,
                client=mock.ANY)
            mock_state.deferred_sync.assert_called_once()


class PlacementReporterAgentsTestCases(test_plugin.Ml2PluginV2TestCase):

    _mechanism_drivers = ['logger', 'test_with_agent']

    def test_supported_agent_types(self):
        self.agents = plugin.PlacementReporterAgents(ml2_plugin=self.plugin)
        self.assertEqual(
            ['test_mechanism_driver_agent'],
            self.agents.supported_agent_types)

    def test_mechanism_driver_by_agent_type_found(self):
        self.agents = plugin.PlacementReporterAgents(ml2_plugin=self.plugin)
        mech_driver = self.agents.mechanism_driver_by_agent_type(
            'test_mechanism_driver_agent')
        self.assertIsInstance(mech_driver, mechanism_test.TestMechanismDriver)

    def test_mechanism_driver_by_agent_type_not_found(self):
        self.agents = plugin.PlacementReporterAgents(ml2_plugin=self.plugin)
        self.assertRaises(
            KeyError,
            self.agents.mechanism_driver_by_agent_type,
            'agent_not_belonging_to_any_mechanism_driver')
