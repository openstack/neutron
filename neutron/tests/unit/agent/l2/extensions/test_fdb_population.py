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

import copy

import mock
from neutron_lib import constants
from neutron_lib.utils import helpers
from oslo_config import cfg
import six

from neutron.agent.l2.extensions.fdb_population import (
        FdbPopulationAgentExtension)
from neutron.plugins.ml2.drivers.linuxbridge.agent.common import (
     constants as linux_bridge_constants)
from neutron.plugins.ml2.drivers.openvswitch.agent.common import (
     constants as ovs_constants)
from neutron.tests import base


class FdbPopulationExtensionTestCase(base.BaseTestCase):

    UPDATE_MSG = {u'device_owner': constants.DEVICE_OWNER_ROUTER_INTF,
                  u'physical_network': u'physnet1',
                  u'mac_address': u'fa:16:3e:ba:bc:21',
                  u'port_id': u'17ceda02-43e1-48d8-beb6-35885b20cae6'}
    DELETE_MSG = {u'port_id': u'17ceda02-43e1-48d8-beb6-35885b20cae6'}
    FDB_TABLE = ("aa:aa:aa:aa:aa:aa self permanent\n"
                 "bb:bb:bb:bb:bb:bb self permanent")

    def setUp(self):
        super(FdbPopulationExtensionTestCase, self).setUp()
        cfg.CONF.set_override('shared_physical_device_mappings',
                              ['physnet1:p1p1'], 'FDB')
        self.DEVICE = self._get_existing_device()

    def _get_existing_device(self):
        device_mappings = helpers.parse_mappings(
            cfg.CONF.FDB.shared_physical_device_mappings, unique_keys=False)
        DEVICES = six.next(six.itervalues(device_mappings))
        return DEVICES[0]

    def _get_fdb_extension(self, mock_execute, fdb_table):
        mock_execute.return_value = fdb_table
        fdb_pop = FdbPopulationAgentExtension()
        fdb_pop.initialize(None, ovs_constants.EXTENSION_DRIVER_TYPE)
        return fdb_pop

    @mock.patch('neutron.agent.linux.utils.execute')
    def test_initialize(self, mock_execute):
        fdb_extension = FdbPopulationAgentExtension()
        fdb_extension.initialize(None, ovs_constants.EXTENSION_DRIVER_TYPE)
        fdb_extension.initialize(None,
                                 linux_bridge_constants.EXTENSION_DRIVER_TYPE)

    @mock.patch('neutron.agent.linux.utils.execute')
    def test_initialize_invalid_agent(self, mock_execute):
        fdb_extension = FdbPopulationAgentExtension()
        self.assertRaises(SystemExit, fdb_extension.initialize, None, 'sriov')

    @mock.patch('neutron.agent.linux.utils.execute')
    def test_construct_empty_fdb_table(self, mock_execute):
        self._get_fdb_extension(mock_execute, fdb_table='')
        cmd = ['bridge', 'fdb', 'show', 'dev', self.DEVICE]
        mock_execute.assert_called_once_with(cmd, run_as_root=True)

    @mock.patch('neutron.agent.linux.utils.execute')
    def test_construct_existing_fdb_table(self, mock_execute):
        fdb_extension = self._get_fdb_extension(mock_execute,
                                                fdb_table=self.FDB_TABLE)
        cmd = ['bridge', 'fdb', 'show', 'dev', self.DEVICE]
        mock_execute.assert_called_once_with(cmd, run_as_root=True)
        updated_macs_for_device = (
            fdb_extension.fdb_tracker.device_to_macs.get(self.DEVICE))
        macs = [line.split()[0] for line in self.FDB_TABLE.split('\n')]
        for mac in macs:
            self.assertIn(mac, updated_macs_for_device)

    @mock.patch('neutron.agent.linux.utils.execute')
    def test_update_port_add_rule(self, mock_execute):
        fdb_extension = self._get_fdb_extension(mock_execute, self.FDB_TABLE)
        mock_execute.reset_mock()
        fdb_extension.handle_port(context=None, details=self.UPDATE_MSG)
        cmd = ['bridge', 'fdb', 'add', self.UPDATE_MSG['mac_address'],
               'dev', self.DEVICE]
        mock_execute.assert_called_once_with(cmd, run_as_root=True)
        updated_macs_for_device = (
            fdb_extension.fdb_tracker.device_to_macs.get(self.DEVICE))
        mac = self.UPDATE_MSG['mac_address']
        self.assertIn(mac, updated_macs_for_device)

    @mock.patch('neutron.agent.linux.utils.execute')
    def test_update_port_changed_mac(self, mock_execute):
        fdb_extension = self._get_fdb_extension(mock_execute, self.FDB_TABLE)
        mock_execute.reset_mock()
        mac = self.UPDATE_MSG['mac_address']
        updated_mac = 'fa:16:3e:ba:bc:33'
        commands = []
        fdb_extension.handle_port(context=None, details=self.UPDATE_MSG)
        commands.append(['bridge', 'fdb', 'add', mac, 'dev', self.DEVICE])
        self.UPDATE_MSG['mac_address'] = updated_mac
        fdb_extension.handle_port(context=None, details=self.UPDATE_MSG)
        commands.append(['bridge', 'fdb', 'delete', mac, 'dev', self.DEVICE])
        commands.append(['bridge', 'fdb', 'add', updated_mac,
                         'dev', self.DEVICE])
        calls = []
        for cmd in commands:
            calls.append(mock.call(cmd, run_as_root=True))
        mock_execute.assert_has_calls(calls)
        updated_macs_for_device = (
            fdb_extension.fdb_tracker.device_to_macs.get(self.DEVICE))
        self.assertIn(updated_mac, updated_macs_for_device)
        self.assertNotIn(mac, updated_macs_for_device)

    @mock.patch('neutron.agent.linux.utils.execute')
    def test_unpermitted_device_owner(self, mock_execute):
        fdb_extension = self._get_fdb_extension(mock_execute, '')
        mock_execute.reset_mock()
        details = copy.deepcopy(self.UPDATE_MSG)
        details['device_owner'] = constants.DEVICE_OWNER_LOADBALANCER
        fdb_extension.handle_port(context=None, details=details)
        self.assertFalse(mock_execute.called)
        updated_macs_for_device = (
            fdb_extension.fdb_tracker.device_to_macs.get(self.DEVICE))
        mac = self.UPDATE_MSG['mac_address']
        self.assertNotIn(mac, updated_macs_for_device)

    @mock.patch('neutron.agent.linux.utils.execute')
    def test_catch_init_exception(self, mock_execute):
        mock_execute.side_effect = RuntimeError
        fdb_extension = self._get_fdb_extension(mock_execute, '')
        updated_macs_for_device = (
            fdb_extension.fdb_tracker.device_to_macs.get(self.DEVICE))
        self.assertIsNone(updated_macs_for_device)

    @mock.patch('neutron.agent.linux.utils.execute')
    def test_catch_update_port_exception(self, mock_execute):
        fdb_extension = self._get_fdb_extension(mock_execute, '')
        mock_execute.side_effect = RuntimeError
        fdb_extension.handle_port(context=None, details=self.UPDATE_MSG)
        updated_macs_for_device = (
            fdb_extension.fdb_tracker.device_to_macs.get(self.DEVICE))
        mac = self.UPDATE_MSG['mac_address']
        self.assertNotIn(mac, updated_macs_for_device)

    @mock.patch('neutron.agent.linux.utils.execute')
    def test_catch_delete_port_exception(self, mock_execute):
        fdb_extension = self._get_fdb_extension(mock_execute, '')
        fdb_extension.handle_port(context=None, details=self.UPDATE_MSG)
        mock_execute.side_effect = RuntimeError
        fdb_extension.delete_port(context=None, details=self.DELETE_MSG)
        updated_macs_for_device = (
            fdb_extension.fdb_tracker.device_to_macs.get(self.DEVICE))
        mac = self.UPDATE_MSG['mac_address']
        self.assertIn(mac, updated_macs_for_device)

    @mock.patch('neutron.agent.linux.utils.execute')
    def test_delete_port(self, mock_execute):
        fdb_extension = self._get_fdb_extension(mock_execute, '')
        fdb_extension.handle_port(context=None, details=self.UPDATE_MSG)
        mock_execute.reset_mock()
        fdb_extension.delete_port(context=None, details=self.DELETE_MSG)
        cmd = ['bridge', 'fdb', 'delete', self.UPDATE_MSG['mac_address'],
               'dev', self.DEVICE]
        mock_execute.assert_called_once_with(cmd, run_as_root=True)

    @mock.patch('neutron.agent.linux.utils.execute')
    def test_multiple_devices(self, mock_execute):
        cfg.CONF.set_override('shared_physical_device_mappings',
                ['physnet1:p1p1', 'physnet1:p2p2'], 'FDB')

        fdb_extension = self._get_fdb_extension(mock_execute, '')
        fdb_extension.handle_port(context=None, details=self.UPDATE_MSG)
        mac = self.UPDATE_MSG['mac_address']
        calls = []
        cmd = ['bridge', 'fdb', 'add', mac, 'dev', 'p1p1']
        calls.append(mock.call(cmd, run_as_root=True))
        cmd = ['bridge', 'fdb', 'add', mac, 'dev', 'p2p2']
        calls.append(mock.call(cmd, run_as_root=True))
        mock_execute.assert_has_calls(calls, any_order=True)
