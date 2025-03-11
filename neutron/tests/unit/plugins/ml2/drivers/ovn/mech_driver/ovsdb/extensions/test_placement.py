# Copyright 2021 Red Hat, Inc.
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

from unittest import mock

from neutron_lib import constants as n_const
from oslo_utils import uuidutils

from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.extensions \
    import placement as p_extension
from neutron.tests.unit import fake_resources as fakes
from neutron.tests.unit.plugins.ml2 import test_plugin


class TestOVNClientPlacementExtension(test_plugin.Ml2PluginV2TestCase):

    CORE_PLUGIN_CLASS = 'neutron.plugins.ml2.plugin.Ml2Plugin'

    def setUp(self):
        super().setUp()
        self.setup_coreplugin(self.CORE_PLUGIN_CLASS, load_plugins=True)
        self.plugin_driver = mock.Mock()
        self.placement_driver = p_extension.OVNClientPlacementExtension(
            self.plugin_driver)
        # Ensure the ``OVNClientPlacementExtension`` object is new, that the
        # previous instance has been deleted.
        self.assertEqual(self.plugin_driver, self.placement_driver._driver)
        self.placement_client = mock.Mock(
            update_trait=mock.Mock(__name__='update_trait'),
            ensure_resource_provider=mock.Mock(__name__='ensure_rp'),
            update_resource_provider_traits=mock.Mock(
                __name__='update_rp_traits'),
            update_resource_provider_inventories=mock.Mock(
                __name__='update_rp_inventories'))
        self.placement_plugin = mock.Mock(
            _placement_client=self.placement_client)
        self.placement_driver._placement_plugin = self.placement_plugin
        self.placement_client.list_resource_providers.return_value = {
            'resource_providers': [{'name': 'compute1', 'uuid': 'uuid1'},
                                   {'name': 'compute2', 'uuid': 'uuid2'}]
        }
        self.name2uuid = self._gen_name2uuid(['compute1',
                                              'compute2',
                                              ])
        self.addCleanup(self._delete_placement_singleton_instance)

    def _delete_placement_singleton_instance(self):
        del self.placement_driver

    @staticmethod
    def _gen_name2uuid(hypervisor_list):
        return {hypervisor: uuidutils.generate_uuid() for
                hypervisor in hypervisor_list}

    def test_read_initial_chassis_config(self):
        # Add two public networks, a RP per bridge and the correlation between
        # the hypervisors and the bridges.
        def _check_expected_config(init_conf, expected):
            res = {chassis_name: p_extension.dict_chassis_config(state) for
                   chassis_name, state in init_conf.items()}
            self.assertEqual(expected, res)

        chassis = fakes.FakeChassis.create(
            bridge_mappings=['public1:br-ext1', 'public2:br-ext2'],
            rp_bandwidths=['br-ext1:1000:2000', 'br-ext2:3000:4000'],
            rp_inventory_defaults={'allocation_ratio': 1.0, 'min_unit': 5},
            rp_hypervisors=['br-ext1:compute1', 'br-ext2:compute2'])
        self.plugin_driver._sb_idl.chassis_list.return_value.execute.\
            return_value = [chassis]
        init_conf = self.placement_driver.read_initial_chassis_config()
        expected = {chassis.name: {
            n_const.RP_BANDWIDTHS: {
                'br-ext1': {'egress': 1000, 'ingress': 2000},
                'br-ext2': {'egress': 3000, 'ingress': 4000}},
            n_const.RP_INVENTORY_DEFAULTS: {
                'allocation_ratio': 1.0, 'min_unit': 5},
            n_const.RP_HYPERVISORS: {
                'br-ext1': {'name': 'compute1', 'uuid': 'uuid1'},
                'br-ext2': {'name': 'compute2', 'uuid': 'uuid2'}}
        }}
        _check_expected_config(init_conf, expected)

        # Add an extra bridge mapping that is discarded because it is not in
        # the hypervisors list (wrong configuration).
        chassis = fakes.FakeChassis.create(
            bridge_mappings=['public1:br-ext1', 'public2:br-ext2',
                             'public3:br-ext3'],
            rp_bandwidths=['br-ext1:1000:2000', 'br-ext2:3000:4000'],
            rp_inventory_defaults={'allocation_ratio': 1.0, 'min_unit': 5},
            rp_hypervisors=['br-ext1:compute1', 'br-ext2:compute2'])
        self.plugin_driver._sb_idl.chassis_list.return_value.execute.\
            return_value = [chassis]
        init_conf = self.placement_driver.read_initial_chassis_config()
        expected = {chassis.name: {
            n_const.RP_BANDWIDTHS: {
                'br-ext1': {'egress': 1000, 'ingress': 2000},
                'br-ext2': {'egress': 3000, 'ingress': 4000}},
            n_const.RP_INVENTORY_DEFAULTS: {
                'allocation_ratio': 1.0, 'min_unit': 5},
            n_const.RP_HYPERVISORS: {
                'br-ext1': {'name': 'compute1', 'uuid': 'uuid1'},
                'br-ext2': {'name': 'compute2', 'uuid': 'uuid2'}}
        }}
        _check_expected_config(init_conf, expected)

        # Add an unknown bridge, not present in the bridge mappings, that is
        # discarded (wrong configuration).
        chassis = fakes.FakeChassis.create(
            bridge_mappings=['public1:br-ext1', 'public2:br-ext2'],
            rp_bandwidths=['br-ext1:1000:2000', 'br-ext3:3000:4000'],
            rp_inventory_defaults={'allocation_ratio': 1.0, 'min_unit': 5},
            rp_hypervisors=['br-ext1:compute1', 'br-ext2:compute2'])
        self.plugin_driver._sb_idl.chassis_list.return_value.execute.\
            return_value = [chassis]
        init_conf = self.placement_driver.read_initial_chassis_config()
        expected = {chassis.name: {
            n_const.RP_BANDWIDTHS: {
                'br-ext1': {'egress': 1000, 'ingress': 2000}},
            n_const.RP_INVENTORY_DEFAULTS: {
                'allocation_ratio': 1.0, 'min_unit': 5},
            n_const.RP_HYPERVISORS: {
                'br-ext1': {'name': 'compute1', 'uuid': 'uuid1'},
                'br-ext2': {'name': 'compute2', 'uuid': 'uuid2'}}
        }}
        _check_expected_config(init_conf, expected)

        # Add an unknown hypervisor, that is not present in the Placement list
        # of resource providers. This hypervisor is discarded (wrong
        # configuration). Because "br-ext2" has no match with an existing
        # hypervisor, is discarded too.
        chassis = fakes.FakeChassis.create(
            bridge_mappings=['public1:br-ext1', 'public2:br-ext2'],
            rp_bandwidths=['br-ext1:1000:2000', 'br-ext2:3000:4000'],
            rp_inventory_defaults={'allocation_ratio': 1.0, 'min_unit': 5},
            rp_hypervisors=['br-ext1:compute1', 'br-ext2:compute3'])
        self.plugin_driver._sb_idl.chassis_list.return_value.execute.\
            return_value = [chassis]
        init_conf = self.placement_driver.read_initial_chassis_config()
        expected = {chassis.name: {
            n_const.RP_BANDWIDTHS: {
                'br-ext1': {'egress': 1000, 'ingress': 2000}},
            n_const.RP_INVENTORY_DEFAULTS: {
                'allocation_ratio': 1.0, 'min_unit': 5},
            n_const.RP_HYPERVISORS: {
                'br-ext1': {'name': 'compute1', 'uuid': 'uuid1'}}
        }}
        _check_expected_config(init_conf, expected)

        # Missing bridge mapping for br-ext2, the RP for this bridge will be
        # discarded.
        chassis = fakes.FakeChassis.create(
            bridge_mappings=['public1:br-ext1'],
            rp_bandwidths=['br-ext1:1000:2000', 'br-ext2:3000:4000'],
            rp_inventory_defaults={'allocation_ratio': 1.0, 'min_unit': 5},
            rp_hypervisors=['br-ext1:compute1', 'br-ext2:compute2'])
        self.plugin_driver._sb_idl.chassis_list.return_value.execute.\
            return_value = [chassis]
        init_conf = self.placement_driver.read_initial_chassis_config()
        expected = {chassis.name: {
            n_const.RP_BANDWIDTHS: {
                'br-ext1': {'egress': 1000, 'ingress': 2000}},
            n_const.RP_INVENTORY_DEFAULTS: {
                'allocation_ratio': 1.0, 'min_unit': 5},
            n_const.RP_HYPERVISORS: {
                'br-ext1': {'name': 'compute1', 'uuid': 'uuid1'},
                'br-ext2': {'name': 'compute2', 'uuid': 'uuid2'}}
        }}
        _check_expected_config(init_conf, expected)

        # No bridge mappings, no RP BW inventories.
        chassis = fakes.FakeChassis.create(
            bridge_mappings=None,
            rp_bandwidths=['br-ext1:1000:2000', 'br-ext2:3000:4000'],
            rp_inventory_defaults={'allocation_ratio': 1.0, 'min_unit': 5},
            rp_hypervisors=['br-ext1:compute1', 'br-ext2:compute2'])
        self.plugin_driver._sb_idl.chassis_list.return_value.execute.\
            return_value = [chassis]
        init_conf = self.placement_driver.read_initial_chassis_config()
        expected = {chassis.name: {
            n_const.RP_BANDWIDTHS: {},
            n_const.RP_INVENTORY_DEFAULTS: {
                'allocation_ratio': 1.0, 'min_unit': 5},
            n_const.RP_HYPERVISORS: {
                'br-ext1': {'name': 'compute1', 'uuid': 'uuid1'},
                'br-ext2': {'name': 'compute2', 'uuid': 'uuid2'}}
        }}
        _check_expected_config(init_conf, expected)

        # No bridge mappings nor hypervisors, no RP BW inventories.
        chassis = fakes.FakeChassis.create(
            bridge_mappings=None,
            rp_bandwidths=['br-ext1:1000:2000', 'br-ext2:3000:4000'],
            rp_inventory_defaults={'allocation_ratio': 1.0, 'min_unit': 5},
            rp_hypervisors=None)
        self.plugin_driver._sb_idl.chassis_list.return_value.execute.\
            return_value = [chassis]
        init_conf = self.placement_driver.read_initial_chassis_config()
        expected = {chassis.name: {
            n_const.RP_BANDWIDTHS: {},
            n_const.RP_INVENTORY_DEFAULTS: {
                'allocation_ratio': 1.0, 'min_unit': 5},
            n_const.RP_HYPERVISORS: {}
        }}
        _check_expected_config(init_conf, expected)

        # If no RP BW information (any deployment not using it), OVN Placement
        # extension won't break anything (sorry for LP#1936983, that was me).
        chassis = fakes.FakeChassis.create(
            bridge_mappings=['public1:br-ext1'],
            rp_bandwidths=None,
            rp_inventory_defaults=None,
            rp_hypervisors=None)
        self.plugin_driver._sb_idl.chassis_list.return_value.execute.\
            return_value = [chassis]
        init_conf = self.placement_driver.read_initial_chassis_config()
        expected = {chassis.name: {
            n_const.RP_BANDWIDTHS: {},
            n_const.RP_INVENTORY_DEFAULTS: {},
            n_const.RP_HYPERVISORS: {}
        }}
        _check_expected_config(init_conf, expected)

        # Test wrongly defined parameters. E.g.:
        # external_ids: {ovn-cms-options={resource_provider_bandwidths=, ...}}
        chassis = fakes.FakeChassis.create(
            bridge_mappings=['public1:br-ext1'],
            rp_bandwidths='',
            rp_inventory_defaults='',
            rp_hypervisors='')
        self.plugin_driver._sb_idl.chassis_list.return_value.execute.\
            return_value = [chassis]
        init_conf = self.placement_driver.read_initial_chassis_config()
        expected = {chassis.name: {
            n_const.RP_BANDWIDTHS: {},
            n_const.RP_INVENTORY_DEFAULTS: {},
            n_const.RP_HYPERVISORS: {}
        }}
        _check_expected_config(init_conf, expected)

    def test_build_placement_state_no_rp_deleted(self):
        chassis = fakes.FakeChassis.create(
            bridge_mappings=['public1:br-ext1', 'public2:br-ext2'],
            rp_bandwidths=['br-ext1:1000:2000', 'br-ext2:3000:4000'],
            rp_inventory_defaults={'allocation_ratio': 1.0, 'min_unit': 5},
            rp_hypervisors=['br-ext1:compute1', 'br-ext2:compute1'])
        chassis_old = fakes.FakeChassis.create(
            bridge_mappings=['public1:br-ext1', 'public2:br-ext2'],
            rp_bandwidths=['br-ext1:1001:2002', 'br-ext2:3003:4004'],
            rp_inventory_defaults={'allocation_ratio': 1.0, 'min_unit': 5},
            rp_hypervisors=['br-ext1:compute1', 'br-ext2:compute1'])
        report = self.placement_driver.build_placement_state(
            chassis, self.name2uuid, chassis_old=chassis_old)
        self.assertEqual(set(), report._rp_deleted)

    def test_build_placement_state_rp_deleted(self):
        chassis = fakes.FakeChassis.create(
            bridge_mappings=['public1:br-ext1', 'public2:br-ext2'],
            rp_bandwidths=['br-ext1:1000:2000'],
            rp_inventory_defaults={'allocation_ratio': 1.0, 'min_unit': 5},
            rp_hypervisors=['br-ext1:compute1', 'br-ext2:compute1'])
        chassis_old = fakes.FakeChassis.create(
            bridge_mappings=['public1:br-ext1', 'public2:br-ext2'],
            rp_bandwidths=['br-ext1:1001:2002', 'br-ext2:3003:4004'],
            rp_inventory_defaults={'allocation_ratio': 1.0, 'min_unit': 5},
            rp_hypervisors=['br-ext1:compute1', 'br-ext2:compute1'])
        report = self.placement_driver.build_placement_state(
            chassis, self.name2uuid, chassis_old=chassis_old)
        self.assertEqual({'br-ext2'}, report._rp_deleted)

    def test_build_placement_state_no_old_chassis(self):
        chassis = fakes.FakeChassis.create(
            bridge_mappings=['public1:br-ext1', 'public2:br-ext2'],
            rp_bandwidths=['br-ext1:1000:2000'],
            rp_inventory_defaults={'allocation_ratio': 1.0, 'min_unit': 5},
            rp_hypervisors=['br-ext1:compute1', 'br-ext2:compute1'])
        report = self.placement_driver.build_placement_state(
            chassis, self.name2uuid)
        self.assertEqual(set(), report._rp_deleted)
