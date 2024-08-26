# Copyright (c) 2016 Mellanox Technologies, Ltd
# All Rights Reserved.
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

from neutron_lib import constants
from neutron_lib.plugins.ml2 import ovs_constants
from neutron_lib.utils import helpers
from oslo_config import cfg
from pyroute2.netlink import exceptions as netlink_exceptions

from neutron.agent.l2.extensions.fdb_population import (
        FdbPopulationAgentExtension)
from neutron.agent.linux import bridge_lib
from neutron.tests import base


class FdbPopulationExtensionTestCase(base.BaseTestCase):

    UPDATE_MSG = {'device_owner': constants.DEVICE_OWNER_ROUTER_INTF,
                  'physical_network': 'physnet1',
                  'mac_address': 'fa:16:3e:ba:bc:21',
                  'port_id': '17ceda02-43e1-48d8-beb6-35885b20cae6'}
    DELETE_MSG = {'port_id': '17ceda02-43e1-48d8-beb6-35885b20cae6'}

    def setUp(self):
        super().setUp()
        cfg.CONF.set_override('shared_physical_device_mappings',
                              ['physnet1:p1p1'], 'FDB')
        self.DEVICE = self._get_existing_device()
        self.mock_add = mock.patch.object(
            bridge_lib.FdbInterface, 'add', return_value=0).start()
        self.mock_append = mock.patch.object(
            bridge_lib.FdbInterface, 'append', return_value=0).start()
        self.mock_replace = mock.patch.object(
            bridge_lib.FdbInterface, 'replace', return_value=0).start()
        self.mock_delete = mock.patch.object(
            bridge_lib.FdbInterface, 'delete', return_value=0).start()
        self.mock_show = mock.patch.object(
            bridge_lib.FdbInterface, 'show').start()

    def _get_existing_device(self):
        device_mappings = helpers.parse_mappings(
            cfg.CONF.FDB.shared_physical_device_mappings, unique_keys=False)
        DEVICES = next(iter(device_mappings.values()))
        return DEVICES[0]

    def _get_fdb_extension(self):
        fdb_pop = FdbPopulationAgentExtension()
        fdb_pop.initialize(None, ovs_constants.EXTENSION_DRIVER_TYPE)
        return fdb_pop

    def test_initialize(self):
        fdb_extension = FdbPopulationAgentExtension()
        fdb_extension.initialize(None, ovs_constants.EXTENSION_DRIVER_TYPE)

    @mock.patch('neutron.agent.common.utils.execute')
    def test_initialize_invalid_agent(self, mock_execute):
        fdb_extension = FdbPopulationAgentExtension()
        self.assertRaises(SystemExit, fdb_extension.initialize, None, 'sriov')

    def test_construct_empty_fdb_table(self):
        self._get_fdb_extension()
        self.mock_show.assert_called_once_with(dev=self.DEVICE)

    def test_construct_existing_fdb_table(self):
        self.mock_show.return_value = {
            self.DEVICE: [{'mac': 'aa:aa:aa:aa:aa:aa'},
                          {'mac': 'bb:bb:bb:bb:bb:bb'}]
        }
        fdb_extension = self._get_fdb_extension()
        self.mock_show.assert_called_once_with(dev=self.DEVICE)
        updated_macs_for_device = (
            fdb_extension.fdb_tracker.device_to_macs.get(self.DEVICE))
        macs = ['aa:aa:aa:aa:aa:aa', 'bb:bb:bb:bb:bb:bb']
        self.assertEqual(sorted(macs), sorted(updated_macs_for_device))

    def test_update_port_add_rule(self):
        fdb_extension = self._get_fdb_extension()
        self.mock_add.return_value = True
        fdb_extension.handle_port(context=None, details=self.UPDATE_MSG)
        self.mock_add.assert_called_once_with(self.UPDATE_MSG['mac_address'],
                                              self.DEVICE)
        updated_macs_for_device = (
            fdb_extension.fdb_tracker.device_to_macs.get(self.DEVICE))
        mac = self.UPDATE_MSG['mac_address']
        self.assertIn(mac, updated_macs_for_device)

    def test_update_port_changed_mac(self):
        fdb_extension = self._get_fdb_extension()
        mac = self.UPDATE_MSG['mac_address']
        updated_mac = 'fa:16:3e:ba:bc:33'
        self.mock_add.return_value = True
        fdb_extension.handle_port(context=None, details=self.UPDATE_MSG)
        self.UPDATE_MSG['mac_address'] = updated_mac
        self.mock_delete.return_value = True
        fdb_extension.handle_port(context=None, details=self.UPDATE_MSG)
        calls_add = [mock.call(mac, self.DEVICE),
                     mock.call(updated_mac, self.DEVICE)]
        self.mock_add.assert_has_calls(calls_add)
        self.mock_delete.assert_called_once_with(mac, self.DEVICE)
        updated_macs_for_device = (
            fdb_extension.fdb_tracker.device_to_macs.get(self.DEVICE))
        self.assertIn(updated_mac, updated_macs_for_device)
        self.assertNotIn(mac, updated_macs_for_device)

    def test_catch_init_exception(self):
        self.mock_add.side_effect = netlink_exceptions.NetlinkError
        fdb_extension = self._get_fdb_extension()
        updated_macs_for_device = (
            fdb_extension.fdb_tracker.device_to_macs.get(self.DEVICE))
        self.assertEqual([], updated_macs_for_device)

    def test_catch_update_port_exception(self):
        fdb_extension = self._get_fdb_extension()
        self.mock_add.return_value = False
        fdb_extension.handle_port(context=None, details=self.UPDATE_MSG)
        updated_macs_for_device = (
            fdb_extension.fdb_tracker.device_to_macs.get(self.DEVICE))
        mac = self.UPDATE_MSG['mac_address']
        self.assertNotIn(mac, updated_macs_for_device)

    def test_catch_delete_port_exception(self):
        fdb_extension = self._get_fdb_extension()
        self.mock_add.return_value = True
        fdb_extension.handle_port(context=None, details=self.UPDATE_MSG)
        self.mock_delete.return_value = False
        fdb_extension.delete_port(context=None, details=self.DELETE_MSG)
        updated_macs_for_device = (
            fdb_extension.fdb_tracker.device_to_macs.get(self.DEVICE))
        self.assertIn(self.UPDATE_MSG['mac_address'], updated_macs_for_device)

    def test_delete_port(self):
        fdb_extension = self._get_fdb_extension()
        self.mock_add.return_value = True
        fdb_extension.handle_port(context=None, details=self.UPDATE_MSG)
        self.mock_delete.return_value = False
        fdb_extension.delete_port(context=None, details=self.DELETE_MSG)
        self.mock_delete.assert_called_once_with(
            self.UPDATE_MSG['mac_address'], self.DEVICE)

    def test_multiple_devices(self):
        cfg.CONF.set_override('shared_physical_device_mappings',
                              ['physnet1:p1p1', 'physnet1:p2p2'], 'FDB')
        fdb_extension = self._get_fdb_extension()
        fdb_extension.handle_port(context=None, details=self.UPDATE_MSG)
        calls = [mock.call(self.UPDATE_MSG['mac_address'], 'p1p1'),
                 mock.call(self.UPDATE_MSG['mac_address'], 'p2p2')]
        self.mock_add.assert_has_calls(calls)
