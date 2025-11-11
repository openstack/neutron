# Copyright 2018 Ericsson
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
import uuid

from neutron_lib.placement import constants as pl_constants
from oslo_config import cfg

from neutron.agent.common import placement_report
from neutron.conf.plugins.ml2 import config as ml2_config
from neutron.tests import base


class DeferredCallTestCase(base.BaseTestCase):

    def test_defer_not_called(self):
        func = mock.Mock()
        placement_report.DeferredCall(func)
        func.assert_not_called()

    def test_execute(self):
        func = mock.Mock()
        deferred = placement_report.DeferredCall(
            func, 'some arg', kwarg='some kwarg')
        deferred.execute()
        func.assert_called_once_with('some arg', kwarg='some kwarg')

    def test___str__(self):
        def func():
            pass
        deferred = placement_report.DeferredCall(func, 42, foo='bar')
        self.assertEqual("func(42, foo='bar')", str(deferred))


class PlacementStateTestCase(base.BaseTestCase):

    def setUp(self):
        ml2_config.register_ml2_plugin_opts()
        super().setUp()
        self.client_mock = mock.Mock()
        self.driver_uuid_namespace = uuid.UUID(
            '00000000-0000-0000-0000-000000000001')
        self.hypervisor1_rp_uuid = uuid.UUID(
            '00000000-0000-0000-0000-000000000002')
        self.hypervisor2_rp_uuid = uuid.UUID(
            '00000000-0000-0000-0000-000000000003')
        self.kwargs = {
            'rp_bandwidths': {},
            'rp_inventory_defaults': {},
            'rp_pkt_processing': {},
            'rp_pkt_processing_inventory_defaults': {},
            'driver_uuid_namespace': self.driver_uuid_namespace,
            'agent_type': 'fake agent type',
            'hypervisor_rps': {
                'eth0': {'name': 'fakehost', 'uuid': self.hypervisor1_rp_uuid},
                'eth1': {'name': 'fakehost', 'uuid': self.hypervisor1_rp_uuid},
                # NOTE(ralonsoh): use the 'rp_tunnelled' n-lib constant once
                # merged.
                'rp_tunnelled': {'name': 'fakehost',
                                 'uuid': self.hypervisor1_rp_uuid},
            },
            'device_mappings': {},
            'supported_vnic_types': [],
            'client': self.client_mock,
        }

    def test__deferred_update_physnet_traits(self):
        self.kwargs.update({
            'device_mappings': {
                'physnet0': ['eth0'],
                'physnet1': ['eth1'],
            },
            'rp_bandwidths': {
                'eth0': {'egress': 1, 'ingress': 1},
            },
        })
        state = placement_report.PlacementState(**self.kwargs)

        for deferred in state._deferred_update_physnet_traits():
            deferred.execute()

        self.client_mock.update_trait.assert_called_with(
            name='CUSTOM_PHYSNET_PHYSNET0')

    def test__deferred_update_vnic_type_traits(self):
        self.kwargs.update({
            'supported_vnic_types': ['direct'],
        })
        state = placement_report.PlacementState(**self.kwargs)

        for deferred in state._deferred_update_vnic_type_traits():
            deferred.execute()

        self.client_mock.update_trait.assert_any_call(
            name='CUSTOM_VNIC_TYPE_DIRECT')

    def test__deferred_update_agent_rp_traits(self):
        self.kwargs['hypervisor_rps']['eth3'] = {
            'name': 'fakehost2',
            'uuid': self.hypervisor2_rp_uuid,
        }
        state = placement_report.PlacementState(**self.kwargs)

        for deferred in state._deferred_update_agent_rp_traits(
                ['CUSTOM_FAKE_TRAIT_NAME']):
            deferred.execute()

        expected_calls = [
            mock.call(
                traits=['CUSTOM_FAKE_TRAIT_NAME'],
                # uuid -v5 '00000000-0000-0000-0000-000000000001' 'fakehost'
                resource_provider_uuid=uuid.UUID(
                    'c0b4abe5-516f-54b8-b965-ff94060dcbcc')),
            mock.call(
                traits=['CUSTOM_FAKE_TRAIT_NAME'],
                # uuid -v5 '00000000-0000-0000-0000-000000000001' 'fakehost2'
                resource_provider_uuid=uuid.UUID(
                    '544155b7-1295-5f10-b5f0-eadc50abc6d4'))]
        self.client_mock.update_resource_provider_traits.\
            assert_has_calls(expected_calls, any_order=True)

    def test__deferred_create_agent_rps(self):
        state = placement_report.PlacementState(**self.kwargs)

        for deferred in state._deferred_create_agent_rps():
            deferred.execute()

        self.client_mock.ensure_resource_provider.assert_called_with(
            resource_provider={
                'name': 'fakehost:fake agent type',
                # uuid below generated by the following command:
                # uuid -v5 '00000000-0000-0000-0000-000000000001' 'fakehost'
                'uuid': uuid.UUID('c0b4abe5-516f-54b8-b965-ff94060dcbcc'),
                'parent_provider_uuid': self.hypervisor1_rp_uuid})

    def test__deferred_create_agent_rps_multiple_hypervisors(self):
        self.kwargs['hypervisor_rps']['eth1'] = {
            'name': 'fakehost2',
            'uuid': self.hypervisor2_rp_uuid,
        }
        state = placement_report.PlacementState(**self.kwargs)

        for deferred in state._deferred_create_agent_rps():
            deferred.execute()

        self.client_mock.ensure_resource_provider.assert_has_calls(
            any_order=True,
            calls=[
                mock.call(resource_provider={
                    'name': 'fakehost:fake agent type',
                    # uuid below generated by the following command:
                    # uuid -v5 '00000000-0000-0000-0000-000000000001' \
                    #          'fakehost'
                    'uuid': uuid.UUID('c0b4abe5-516f-54b8-b965-ff94060dcbcc'),
                    'parent_provider_uuid': self.hypervisor1_rp_uuid}),
                mock.call(resource_provider={
                    'name': 'fakehost2:fake agent type',
                    # uuid below generated by the following command:
                    # uuid -v5 '00000000-0000-0000-0000-000000000001' \
                    #          'fakehost2'
                    'uuid': uuid.UUID('544155b7-1295-5f10-b5f0-eadc50abc6d4'),
                    'parent_provider_uuid': self.hypervisor2_rp_uuid}),
            ]
        )

    def test_deferred_create_resource_providers(self):
        self.kwargs.update({
            'rp_bandwidths': {
                'eth0': {'egress': 1, 'ingress': 1},
            },
        })
        state = placement_report.PlacementState(**self.kwargs)

        for deferred in state.deferred_create_resource_providers():
            deferred.execute()

        self.client_mock.ensure_resource_provider.assert_called_with(
            {'name': 'fakehost:fake agent type:eth0',
             # uuid below generated by the following command:
             # uuid -v5 '00000000-0000-0000-0000-000000000001'
             #          'fakehost:eth0'
             'uuid': uuid.UUID('1ea6f823-bcf2-5dc5-9bee-4ee6177a6451'),
             # uuid below generated by the following command:
             # uuid -v5 '00000000-0000-0000-0000-000000000001' 'fakehost'
             'parent_provider_uuid': uuid.UUID(
                 'c0b4abe5-516f-54b8-b965-ff94060dcbcc')})

    def test_deferred_update_resource_provider_traits(self):
        self.kwargs.update({
            'device_mappings': {
                'physnet0': ['eth0'],
            },
            'rp_bandwidths': {
                'eth0': {'egress': 1, 'ingress': 1},
                'rp_tunnelled': {'egress': 2, 'ingress': 3},
            },
            'supported_vnic_types': ['normal'],
        })
        state = placement_report.PlacementState(**self.kwargs)

        for deferred in state.deferred_update_resource_provider_traits():
            deferred.execute()

        expected_calls = [
            # uuid below generated by the following command:
            # uuid -v5 '00000000-0000-0000-0000-000000000001' 'fakehost:eth0'
            mock.call(
                resource_provider_uuid=uuid.UUID(
                    '1ea6f823-bcf2-5dc5-9bee-4ee6177a6451'),
                traits=mock.ANY),

            # uuid -v5 '00000000-0000-0000-0000-000000000001' \
            # 'fakehost:rp_tunnelled'
            mock.call(
                resource_provider_uuid=uuid.UUID(
                    '357001cb-88b4-5e1d-ae6e-85b238a7a83e'),
                traits=mock.ANY),

            # uuid -v5 '00000000-0000-0000-0000-000000000001' 'fakehost'
            mock.call(
                resource_provider_uuid=uuid.UUID(
                    'c0b4abe5-516f-54b8-b965-ff94060dcbcc'),
                traits=mock.ANY)]
        self.client_mock.update_resource_provider_traits.assert_has_calls(
            expected_calls)

        # NOTE(bence romsics): To avoid testing the _order_ of traits.
        actual_traits = [
            set(args[1]['traits']) for args in
            self.client_mock.update_resource_provider_traits.call_args_list]
        self.assertEqual(
            [{'CUSTOM_PHYSNET_PHYSNET0', 'CUSTOM_VNIC_TYPE_NORMAL'},
             {pl_constants.TRAIT_NETWORK_TUNNEL, 'CUSTOM_VNIC_TYPE_NORMAL'},
             {'CUSTOM_VNIC_TYPE_NORMAL'}],
            actual_traits)

    def test_deferred_update_resource_provider_traits_shared_rp(self):
        self.kwargs.update({
            'device_mappings': {
                'physnet0': ['eth0'],
            },
            'rp_bandwidths': {
                'eth0': {'egress': 1, 'ingress': 1},
            },
            'supported_vnic_types': ['normal'],
        })
        cfg.CONF.set_override('tunnelled_network_rp_name', 'eth0', group='ml2')
        state = placement_report.PlacementState(**self.kwargs)

        for deferred in state.deferred_update_resource_provider_traits():
            deferred.execute()

        expected_calls = [
            # uuid below generated by the following command:
            # uuid -v5 '00000000-0000-0000-0000-000000000001' 'fakehost:eth0'
            mock.call(
                resource_provider_uuid=uuid.UUID(
                    '1ea6f823-bcf2-5dc5-9bee-4ee6177a6451'),
                traits=mock.ANY),

            # uuid -v5 '00000000-0000-0000-0000-000000000001' 'fakehost'
            mock.call(
                resource_provider_uuid=uuid.UUID(
                    'c0b4abe5-516f-54b8-b965-ff94060dcbcc'),
                traits=mock.ANY)]
        self.client_mock.update_resource_provider_traits.assert_has_calls(
            expected_calls)

        # NOTE(bence romsics): To avoid testing the _order_ of traits.
        actual_traits = [
            set(args[1]['traits']) for args in
            self.client_mock.update_resource_provider_traits.call_args_list]
        self.assertEqual(
            [{pl_constants.TRAIT_NETWORK_TUNNEL, 'CUSTOM_PHYSNET_PHYSNET0',
              'CUSTOM_VNIC_TYPE_NORMAL'},
             {'CUSTOM_VNIC_TYPE_NORMAL'}],
            actual_traits)

    def test_deferred_update_resource_provider_inventories_bw(self):
        self.kwargs.update({
            'device_mappings': {
                'physnet0': ['eth0'],
            },
            'rp_bandwidths': {
                'eth0': {'egress': 100, 'ingress': None},
            },
            'rp_inventory_defaults': {
                'step_size': 10,
                'max_unit': 50,
            },
        })
        state = placement_report.PlacementState(**self.kwargs)

        for deferred in state.deferred_update_resource_provider_inventories():
            deferred.execute()

        self.client_mock.\
            update_resource_provider_inventories.assert_called_with(
                # uuid below generated by the following command:
                # uuid -v5 '00000000-0000-0000-0000-000000000001' \
                #          'fakehost:eth0'
                resource_provider_uuid=uuid.UUID(
                    '1ea6f823-bcf2-5dc5-9bee-4ee6177a6451'),
                inventories={
                    'NET_BW_EGR_KILOBIT_PER_SEC': {
                        'total': 100,
                        'step_size': 10,
                        'max_unit': 50}})

    def test_deferred_update_resource_provider_inventories_pp_direction(self):
        self.kwargs.update({
            'rp_pkt_processing': {
                'fakehost': {'egress': 100, 'ingress': 200},
            },
            'rp_pkt_processing_inventory_defaults': {
                'step_size': 10,
                'max_unit': 50,
            },
        })
        state = placement_report.PlacementState(**self.kwargs)

        for deferred in state.deferred_update_resource_provider_inventories():
            deferred.execute()

        # uuid below generated by the following command:
        # uuid -v5 '00000000-0000-0000-0000-000000000001' 'fakehost'
        expected_calls = [
            mock.call(
                resource_provider_uuid=uuid.UUID(
                    'c0b4abe5-516f-54b8-b965-ff94060dcbcc'),
                inventories={
                    # TODO(przszc): Replace hard-coded resource classes names
                    # with os-resource-classes lib.
                    'NET_PACKET_RATE_EGR_KILOPACKET_PER_SEC': {
                        'total': 100,
                        'step_size': 10,
                        'max_unit': 50},
                    'NET_PACKET_RATE_IGR_KILOPACKET_PER_SEC': {
                        'total': 200,
                        'step_size': 10,
                        'max_unit': 50}})]
        self.client_mock.update_resource_provider_inventories.assert_has_calls(
            expected_calls)

    def test_deferred_update_resource_provider_inventories_pp(self):
        self.kwargs.update({
            'rp_pkt_processing': {
                'fakehost': {'any': 300},
            },
            'rp_pkt_processing_inventory_defaults': {
                'step_size': 1,
                'max_unit': 5,
            },
        })
        state = placement_report.PlacementState(**self.kwargs)

        for deferred in state.deferred_update_resource_provider_inventories():
            deferred.execute()

        # uuid below generated by the following command:
        # uuid -v5 '00000000-0000-0000-0000-000000000001' 'fakehost'
        expected_calls = [
            mock.call(
                resource_provider_uuid=uuid.UUID(
                    'c0b4abe5-516f-54b8-b965-ff94060dcbcc'),
                inventories={
                    'NET_PACKET_RATE_KILOPACKET_PER_SEC': {
                        'total': 300,
                        'step_size': 1,
                        'max_unit': 5}})]
        self.client_mock.update_resource_provider_inventories.assert_has_calls(
            expected_calls)
