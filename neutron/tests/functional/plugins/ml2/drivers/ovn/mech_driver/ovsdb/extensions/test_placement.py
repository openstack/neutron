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
from neutron_lib.plugins import constants as plugins_constants
from oslo_utils import uuidutils

from neutron.common.ovn import constants as ovn_const
from neutron.common import utils as common_utils
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.extensions \
    import placement as placement_extension
from neutron.tests.functional import base
from neutron.tests.functional.plugins.ml2.drivers.ovn.mech_driver.ovsdb \
    import test_ovsdb_monitor


class TestOVNClientPlacementExtension(base.TestOVNFunctionalBase):

    EMPTY_CHASSIS = {n_const.RP_BANDWIDTHS: {},
                     n_const.RP_INVENTORY_DEFAULTS: {},
                     ovn_const.RP_HYPERVISORS: {}}

    RP_BANDWIDTHS_1 = {'br-provider0': {'egress': 1000, 'ingress': 2000}}
    RP_INVENTORY_DEFAULTS_1 = {'allocation_ratio': 1.0, 'min_unit': 2}
    RP_HYPERVISORS_1 = {'br-provider0': {'name': 'host1', 'uuid': 'uuid1'}}
    CHASSIS1 = {
        'chassis1': {
            n_const.RP_BANDWIDTHS: RP_BANDWIDTHS_1,
            n_const.RP_INVENTORY_DEFAULTS: RP_INVENTORY_DEFAULTS_1,
            ovn_const.RP_HYPERVISORS: RP_HYPERVISORS_1
        }
    }
    RP_BANDWIDTHS_2 = {'br-provider0': {'egress': 3000, 'ingress': 4000}}
    RP_INVENTORY_DEFAULTS_2 = {'allocation_ratio': 3.0, 'min_unit': 1}
    RP_HYPERVISORS_2 = {'br-provider0': {'name': 'host2', 'uuid': 'uuid2'}}
    CHASSIS2 = {
        'chassis2': {
            n_const.RP_BANDWIDTHS: RP_BANDWIDTHS_2,
            n_const.RP_INVENTORY_DEFAULTS: RP_INVENTORY_DEFAULTS_2,
            ovn_const.RP_HYPERVISORS: RP_HYPERVISORS_2
        }
    }

    RP_BANDWIDTHS_3 = {'br-provider0': {'egress': 5000, 'ingress': 6000}}
    RP_INVENTORY_DEFAULTS_3 = {'allocation_ratio': 1.1, 'min_unit': 1}
    CHASSIS2_B = {
        'chassis2': {
            n_const.RP_BANDWIDTHS: RP_BANDWIDTHS_3,
            n_const.RP_INVENTORY_DEFAULTS: RP_INVENTORY_DEFAULTS_3,
            ovn_const.RP_HYPERVISORS: RP_HYPERVISORS_2
        }
    }

    def setUp(self, maintenance_worker=False, service_plugins=None):
        service_plugins = {plugins_constants.PLACEMENT_REPORT: 'placement'}
        super().setUp(maintenance_worker=maintenance_worker,
                      service_plugins=service_plugins)
        self.ovn_client = self.mech_driver._ovn_client
        self.placement_ext = self.ovn_client.placement_extension
        self.mock_name2uuid = mock.patch.object(
            self.placement_ext, 'name2uuid').start()
        self.mock_send_batch = mock.patch.object(
            placement_extension, '_send_deferred_batch').start()

    def _build_other_config(self, bandwidths, inventory_defaults, hypervisors):
        options = []
        if bandwidths:
            options.append(n_const.RP_BANDWIDTHS + '=' + bandwidths)
        if inventory_defaults:
            options.append(n_const.RP_INVENTORY_DEFAULTS + '=' +
                           inventory_defaults)
        if hypervisors:
            options.append(ovn_const.RP_HYPERVISORS + '=' + hypervisors)
        return {'ovn-cms-options': ','.join(options)}

    def _create_chassis(self, host, name, physical_nets=None, bandwidths=None,
                        inventory_defaults=None, hypervisors=None):
        other_config = self._build_other_config(bandwidths, inventory_defaults,
                                                hypervisors)
        self.add_fake_chassis(host, physical_nets=physical_nets,
                              other_config=other_config, name=name)

    def _update_chassis(self, name, bandwidths=None, inventory_defaults=None,
                        hypervisors=None):
        other_config = self._build_other_config(bandwidths, inventory_defaults,
                                                hypervisors)
        self.sb_api.db_set(
            'Chassis', name, ('other_config', other_config)
        ).execute(check_error=True)

    def _check_placement_config(self, expected_chassis):
        current_chassis = None

        def check_chassis():
            nonlocal current_chassis
            current_chassis = self.placement_ext.get_chassis_config()
            current_chassis = {
                chassis_name: placement_extension.dict_chassis_config(state)
                for chassis_name, state in current_chassis.items()}
            return current_chassis == expected_chassis

        try:
            common_utils.wait_until_true(check_chassis, timeout=5)
        except common_utils.WaitTimeout:
            self.fail('OVN client Placement extension cache does not have '
                      'the expected chassis information.\nExpected: %s.\n'
                      'Actual: %s' % (expected_chassis, current_chassis))

    def test_read_initial_config_and_update(self):
        self.mock_name2uuid.return_value = {'host1': 'uuid1',
                                            'host2': 'uuid2'}
        self._create_chassis(
            'host1', 'chassis1', physical_nets=['phys1'],
            bandwidths='br-provider0:1000:2000',
            inventory_defaults='allocation_ratio:1.0;min_unit:2',
            hypervisors='br-provider0:host1')
        self._create_chassis(
            'host2', 'chassis2', physical_nets=['phys2'],
            bandwidths='br-provider0:3000:4000',
            inventory_defaults='allocation_ratio:3.0;min_unit:1',
            hypervisors='br-provider0:host2')
        self._check_placement_config({**self.CHASSIS1, **self.CHASSIS2})

        self._update_chassis(
            'chassis2',
            bandwidths='br-provider0:5000:6000',
            inventory_defaults='allocation_ratio:1.1;min_unit:1',
            hypervisors='br-provider0:host2')
        self._check_placement_config({**self.CHASSIS1, **self.CHASSIS2_B})

    def test_read_initial_empty_config_and_update(self):
        self.mock_name2uuid.return_value = {'host1': 'uuid1',
                                            'host2': 'uuid2'}
        self._create_chassis('host1', 'chassis1', physical_nets=['phys1'])
        self._create_chassis('host2', 'chassis2', physical_nets=['phys2'])
        self._check_placement_config({**{'chassis1': self.EMPTY_CHASSIS},
                                      **{'chassis2': self.EMPTY_CHASSIS}})

        self._update_chassis(
            'chassis1',
            bandwidths='br-provider0:1000:2000',
            inventory_defaults='allocation_ratio:1.0;min_unit:2',
            hypervisors='br-provider0:host1')
        self._check_placement_config({**self.CHASSIS1,
                                      **{'chassis2': self.EMPTY_CHASSIS}})

        self._update_chassis(
            'chassis2',
            bandwidths='br-provider0:3000:4000',
            inventory_defaults='allocation_ratio:3.0;min_unit:1',
            hypervisors='br-provider0:host2')
        self._check_placement_config({**self.CHASSIS1, **self.CHASSIS2})

    def test_update_twice(self):
        self.mock_name2uuid.return_value = {'host1': 'uuid1',
                                            'host2': 'uuid2'}
        self._create_chassis(
            'host1', 'chassis1', physical_nets=['phys1'],
            bandwidths='br-provider0:1000:2000',
            inventory_defaults='allocation_ratio:1.0;min_unit:2',
            hypervisors='br-provider0:host1')
        self._create_chassis('host2', 'chassis2', physical_nets=['phys2'])
        self._check_placement_config({**self.CHASSIS1,
                                      **{'chassis2': self.EMPTY_CHASSIS}})

        self._update_chassis(
            'chassis2',
            bandwidths='br-provider0:3000:4000',
            inventory_defaults='allocation_ratio:3.0;min_unit:1',
            hypervisors='br-provider0:host2')
        self._check_placement_config({**self.CHASSIS1, **self.CHASSIS2})

        self._update_chassis(
            'chassis2',
            bandwidths='br-provider0:5000:6000',
            inventory_defaults='allocation_ratio:1.1;min_unit:1',
            hypervisors='br-provider0:host2')
        self._check_placement_config({**self.CHASSIS1, **self.CHASSIS2_B})

    @mock.patch.object(placement_extension, '_send_deferred_batch')
    def test_chassis_bandwidth_config_event(self, mock_send_placement):
        ch_host = 'fake-chassis-host'
        ch_name = uuidutils.generate_uuid()
        ch_event = test_ovsdb_monitor.WaitForChassisPrivateCreateEvent(
            ch_name, self.mech_driver.agent_chassis_table)
        self.mech_driver.sb_ovn.idl.notify_handler.watch_event(ch_event)
        self.chassis_name = self.add_fake_chassis(ch_host, name=ch_name)
        self.assertTrue(ch_event.wait())
        common_utils.wait_until_true(lambda: mock_send_placement.called,
                                     timeout=2)
        mock_send_placement.reset_mock()

        # Once the chassis registger has been created, this new event will
        # catch any chassis BW update.
        self._update_chassis(
            ch_name,
            bandwidths='br-provider0:3000:4000',
            inventory_defaults='allocation_ratio:3.0;min_unit:1',
            hypervisors='br-provider0:host2')
        common_utils.wait_until_true(lambda: mock_send_placement.called,
                                     timeout=2)
        mock_send_placement.reset_mock()

        # The chassis BW information is written again without any change.
        # That should not trigger the placement update.
        self._update_chassis(
            ch_name,
            bandwidths='br-provider0:3000:4000',
            inventory_defaults='allocation_ratio:3.0;min_unit:1',
            hypervisors='br-provider0:host2')
        self.assertRaises(common_utils.WaitTimeout,
                          common_utils.wait_until_true,
                          lambda: mock_send_placement.called,
                          timeout=2)
