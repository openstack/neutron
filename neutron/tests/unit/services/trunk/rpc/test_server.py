# Copyright 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from unittest import mock

from neutron_lib.api.definitions import portbindings
from neutron_lib.db import api as db_api
from neutron_lib.plugins import directory
from neutron_lib import rpc as n_rpc
from neutron_lib.services.trunk import constants
from sqlalchemy.orm import exc

from neutron.api.rpc.callbacks import events
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import resources_rpc
from neutron.objects import trunk as trunk_obj
from neutron.plugins.ml2 import plugin as ml2_plugin
from neutron.services.trunk import drivers
from neutron.services.trunk import exceptions as trunk_exc
from neutron.services.trunk import plugin as trunk_plugin
from neutron.services.trunk.rpc import server
from neutron.tests import base
from neutron.tests.unit.plugins.ml2 import test_plugin


class TrunkSkeletonTest(test_plugin.Ml2PluginV2TestCase):
    def setUp(self):
        super(TrunkSkeletonTest, self).setUp()
        self.mock_registry_provide = mock.patch(
            'neutron.api.rpc.callbacks.producer.registry.provide').start()
        self.drivers_patch = mock.patch.object(drivers, 'register').start()
        self.mock_update_port = mock.patch.object(ml2_plugin.Ml2Plugin,
                                                  'update_port').start()
        self.compat_patch = mock.patch.object(
            trunk_plugin.TrunkPlugin, 'check_compatibility').start()
        self.trunk_plugin = trunk_plugin.TrunkPlugin()
        self.trunk_plugin.add_segmentation_type('vlan', lambda x: True)
        self.core_plugin = directory.get_plugin()

    def _create_test_trunk(self, port, subports=None):
        subports = subports if subports else []
        trunk = {'port_id': port['port']['id'],
                 'tenant_id': 'test_tenant',
                 'sub_ports': subports
                 }
        response = (
            self.trunk_plugin.create_trunk(self.context, {'trunk': trunk}))
        return response

    @mock.patch("neutron.api.rpc.callbacks.resource_manager."
                "ResourceCallbacksManager.register")
    def test___init__(self, mocked_get_server):
        mock_conn = mock.MagicMock()
        with mock.patch.object(n_rpc.Connection, 'create_consumer',
                               new_callable=mock_conn):
            test_obj = server.TrunkSkeleton()
            self.mock_registry_provide.assert_called_with(
                server.trunk_by_port_provider,
                resources.TRUNK)
            self.assertItemsEqual(('trunk', [test_obj],),
                                  mock_conn.mock_calls[1][1])

    def test_update_subport_bindings(self):
        with self.port() as _parent_port:
            parent_port = _parent_port
        trunk = self._create_test_trunk(parent_port)
        port_data = {portbindings.HOST_ID: 'trunk_host_id'}
        self.core_plugin.update_port(
            self.context, parent_port['port']['id'], {'port': port_data})
        subports = []
        mock_return_vals = []
        for vid in range(0, 3):
            with self.port() as new_port:
                new_port[portbindings.HOST_ID] = 'trunk_host_id'
                mock_return_vals.append(new_port)
                obj = trunk_obj.SubPort(
                    context=self.context,
                    trunk_id=trunk['id'],
                    port_id=new_port['port']['id'],
                    segmentation_type='vlan',
                    segmentation_id=vid)
                subports.append(obj)

        self.mock_update_port.side_effect = mock_return_vals
        test_obj = server.TrunkSkeleton()
        test_obj._trunk_plugin = self.trunk_plugin
        test_obj._core_plugin = self.core_plugin
        updated_subports = test_obj.update_subport_bindings(self.context,
                                                            subports=subports)
        trunk = trunk_obj.Trunk.get_object(self.context, id=trunk['id'])

        self.assertEqual(trunk.status, constants.TRUNK_BUILD_STATUS)
        self.assertIn(trunk.id, updated_subports)
        for port in updated_subports[trunk['id']]:
            self.assertEqual('trunk_host_id', port[portbindings.HOST_ID])

    def test_update_subport_bindings_during_migration(self):
        with self.port() as _parent_port:
            parent_port = _parent_port
        trunk = self._create_test_trunk(parent_port)
        subports = []
        for vid in range(0, 3):
            with self.port() as new_port:
                obj = trunk_obj.SubPort(
                    context=self.context,
                    trunk_id=trunk['id'],
                    port_id=new_port['port']['id'],
                    segmentation_type='vlan',
                    segmentation_id=vid)
                subports.append(obj)

        expected_calls = [
            mock.call(
                mock.ANY, subport['port_id'],
                {'port': {portbindings.HOST_ID: 'new_trunk_host_id',
                          'device_owner': constants.TRUNK_SUBPORT_OWNER}})
            for subport in subports]

        test_obj = server.TrunkSkeleton()
        test_obj._trunk_plugin = self.trunk_plugin
        test_obj._core_plugin = self.core_plugin
        port_data = {
            portbindings.HOST_ID: 'trunk_host_id',
            portbindings.PROFILE: {'migrating_to': 'new_trunk_host_id'}}
        with mock.patch.object(
                self.core_plugin, "get_port",
                return_value=port_data), \
            mock.patch.object(
                test_obj, "_safe_update_trunk"):
            test_obj.update_subport_bindings(self.context, subports=subports)
        for expected_call in expected_calls:
            self.assertIn(expected_call, self.mock_update_port.mock_calls)

    def test__handle_port_binding_binding_error(self):
        with self.port() as _trunk_port:
            trunk = self._create_test_trunk(_trunk_port)
            trunk_host = 'test-host'
            test_obj = server.TrunkSkeleton()
            self.mock_update_port.return_value = {portbindings.VIF_TYPE:
                                         portbindings.VIF_TYPE_BINDING_FAILED}
            self.assertRaises(trunk_exc.SubPortBindingError,
                              test_obj._handle_port_binding,
                              self.context,
                              _trunk_port['port']['id'],
                              trunk_obj.Trunk.get_object(self.context,
                                                         id=trunk['id']),
                              trunk_host)

    def test_udate_subport_bindings_error(self):
        with self.port() as _parent_port:
            parent_port = _parent_port
        trunk = self._create_test_trunk(parent_port)
        port_data = {portbindings.HOST_ID: 'trunk_host_id'}
        self.core_plugin.update_port(
            self.context, parent_port['port']['id'], {'port': port_data})
        subports = []
        for vid in range(0, 3):
            with self.port() as new_port:
                new_port[portbindings.HOST_ID] = 'trunk_host_id'
                obj = trunk_obj.SubPort(
                    context=self.context,
                    trunk_id=trunk['id'],
                    port_id=new_port['port']['id'],
                    segmentation_type='vlan',
                    segmentation_id=vid)
                subports.append(obj)

        test_obj = server.TrunkSkeleton()
        test_obj._trunk_plugin = self.trunk_plugin
        test_obj._core_plugin = self.core_plugin
        self.mock_update_port.return_value = {portbindings.VIF_TYPE:
                                         portbindings.VIF_TYPE_BINDING_FAILED}
        updated_subports = test_obj.update_subport_bindings(self.context,
                                                            subports=subports)
        trunk = trunk_obj.Trunk.get_object(self.context, id=trunk['id'])

        self.assertEqual(trunk.status, constants.TRUNK_ERROR_STATUS)
        self.assertEqual([], updated_subports[trunk.id])

    def test_udate_subport_bindings_staledataerror(self):
        with self.port() as _parent_port:
            parent_port = _parent_port
        trunk = self._create_test_trunk(parent_port)
        port_data = {portbindings.HOST_ID: 'trunk_host_id'}
        self.core_plugin.update_port(
            self.context, parent_port['port']['id'], {'port': port_data})
        subports = []
        for vid in range(0, 3):
            with self.port() as new_port:
                new_port[portbindings.HOST_ID] = 'trunk_host_id'
                obj = trunk_obj.SubPort(
                    context=self.context,
                    trunk_id=trunk['id'],
                    port_id=new_port['port']['id'],
                    segmentation_type='vlan',
                    segmentation_id=vid)
                subports.append(obj)

        test_obj = server.TrunkSkeleton()
        test_obj._trunk_plugin = self.trunk_plugin
        test_obj._core_plugin = self.core_plugin
        self.mock_update_port.return_value = {portbindings.VIF_TYPE:
                                         portbindings.VIF_TYPE_BINDING_FAILED}
        mock_trunk_obj = mock.Mock(port_id=parent_port['port']['id'])
        mock_trunk_obj.update.side_effect = exc.StaleDataError

        with mock.patch.object(
                trunk_obj.Trunk,
                'get_object',
                return_value=mock_trunk_obj):
            self.assertRaises(
                exc.StaleDataError,
                test_obj.update_subport_bindings,
                self.context,
                subports=subports)
            self.assertEqual(
                db_api.MAX_RETRIES,
                mock_trunk_obj.update.call_count)

    def test_udate_subport_bindings_noretryerror(self):
        with self.port() as _parent_port:
            parent_port = _parent_port
        trunk = self._create_test_trunk(parent_port)
        port_data = {portbindings.HOST_ID: 'trunk_host_id'}
        self.core_plugin.update_port(
            self.context, parent_port['port']['id'], {'port': port_data})
        subports = []
        for vid in range(0, 3):
            with self.port() as new_port:
                new_port[portbindings.HOST_ID] = 'trunk_host_id'
                obj = trunk_obj.SubPort(
                    context=self.context,
                    trunk_id=trunk['id'],
                    port_id=new_port['port']['id'],
                    segmentation_type='vlan',
                    segmentation_id=vid)
                subports.append(obj)

        test_obj = server.TrunkSkeleton()
        test_obj._trunk_plugin = self.trunk_plugin
        test_obj._core_plugin = self.core_plugin
        self.mock_update_port.return_value = {portbindings.VIF_TYPE:
                                         portbindings.VIF_TYPE_BINDING_FAILED}
        mock_trunk_obj = mock.Mock(port_id=parent_port['port']['id'])
        mock_trunk_obj.update.side_effect = KeyError

        with mock.patch.object(
                trunk_obj.Trunk,
                'get_object',
                return_value=mock_trunk_obj):
            self.assertRaises(
                KeyError,
                test_obj.update_subport_bindings,
                self.context,
                subports=subports)
            self.assertEqual(1, mock_trunk_obj.update.call_count)

    def test_update_subport_bindings_exception(self):
        with self.port() as _parent_port:
            parent_port = _parent_port
        trunk = self._create_test_trunk(parent_port)
        port_data = {portbindings.HOST_ID: 'trunk_host_id'}
        self.core_plugin.update_port(
            self.context, parent_port['port']['id'], {'port': port_data})
        subports = []
        mock_return_vals = []
        for vid in range(0, 3):
            with self.port() as new_port:
                new_port[portbindings.HOST_ID] = 'trunk_host_id'
                mock_return_vals.append(new_port)
                obj = trunk_obj.SubPort(
                    context=self.context,
                    trunk_id=trunk['id'],
                    port_id=new_port['port']['id'],
                    segmentation_type='vlan',
                    segmentation_id=vid)
                subports.append(obj)

        self.mock_update_port.side_effect = Exception()
        test_obj = server.TrunkSkeleton()
        test_obj._trunk_plugin = self.trunk_plugin
        test_obj._core_plugin = self.core_plugin
        updated_subports = test_obj.update_subport_bindings(self.context,
                                                            subports=subports)
        trunk = trunk_obj.Trunk.get_object(self.context, id=trunk['id'])
        self.assertEqual([], updated_subports.get(trunk.id))
        self.assertEqual(constants.TRUNK_DEGRADED_STATUS, trunk.status)


class TrunkStubTest(base.BaseTestCase):
    def setUp(self):
        super(TrunkStubTest, self).setUp()
        self.test_obj = server.TrunkStub()

    def test___init__(self):
        self.assertIsInstance(self.test_obj._resource_rpc,
                              resources_rpc.ResourcesPushRpcApi)

    @mock.patch("neutron.api.rpc.handlers.resources_rpc.ResourcesPushRpcApi."
                "push")
    def test_trunk_created(self, mocked_push):
        m_context = mock.Mock()
        m_trunk = mock.Mock()
        self.test_obj.trunk_created(m_context, m_trunk)
        mocked_push.assert_called_with(m_context, [m_trunk], events.CREATED)

    @mock.patch("neutron.api.rpc.handlers.resources_rpc.ResourcesPushRpcApi."
                "push")
    def test_trunk_deleted(self, mocked_push):
        m_context = mock.Mock()
        m_trunk = mock.Mock()
        self.test_obj.trunk_deleted(m_context, m_trunk)
        mocked_push.assert_called_with(m_context, [m_trunk], events.DELETED)

    @mock.patch("neutron.api.rpc.handlers.resources_rpc.ResourcesPushRpcApi."
                "push")
    def test_subports_added(self, mocked_push):
        m_context = mock.Mock()
        m_subports = mock.Mock()
        self.test_obj.subports_added(m_context, m_subports)
        mocked_push.assert_called_with(m_context, m_subports, events.CREATED)

    @mock.patch("neutron.api.rpc.handlers.resources_rpc.ResourcesPushRpcApi."
                "push")
    def test_subports_deleted(self, mocked_push):
        m_context = mock.Mock()
        m_subports = mock.Mock()
        self.test_obj.subports_deleted(m_context, m_subports)
        mocked_push.assert_called_with(m_context, m_subports, events.DELETED)
