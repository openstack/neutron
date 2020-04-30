# Copyright (c) 2019 Red Hat, Inc.
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

from neutron_lib import context
from neutron_lib import exceptions as lib_exc
from neutron_lib.objects import exceptions as obj_exc
from neutron_lib.plugins import directory
from oslo_config import cfg

from neutron.api.rpc.callbacks.consumer import registry as cons_registry
from neutron.api.rpc.callbacks import events as rpc_events
from neutron.api.rpc.callbacks.producer import registry as prod_registry
from neutron.api.rpc.callbacks import resource_manager
from neutron.api.rpc.handlers import resources_rpc
from neutron import manager
from neutron.objects import conntrack_helper
from neutron.services.conntrack_helper.common import exceptions as cth_exc
from neutron.services.conntrack_helper import plugin as cth_plugin
from neutron.tests.unit import testlib_api

DB_PLUGIN_KLASS = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'


class TestConntrackHelperPlugin(testlib_api.SqlTestCase):

    def setUp(self):
        super(TestConntrackHelperPlugin, self).setUp()

        with mock.patch.object(
                resource_manager.ResourceCallbacksManager, '_singleton',
                new_callable=mock.PropertyMock(return_value=False)):

            self.cons_mgr = resource_manager.ConsumerResourceCallbacksManager()
            self.prod_mgr = resource_manager.ProducerResourceCallbacksManager()
            for mgr in (self.cons_mgr, self.prod_mgr):
                mgr.clear()

        mock.patch.object(
            cons_registry, '_get_manager', return_value=self.cons_mgr).start()

        mock.patch.object(
            prod_registry, '_get_manager', return_value=self.prod_mgr).start()
        self.setup_coreplugin(load_plugins=False)

        mock.patch('neutron.objects.db.api.create_object').start()
        mock.patch('neutron.objects.db.api.update_object').start()
        mock.patch('neutron.objects.db.api.delete_object').start()
        mock.patch('neutron.objects.db.api.get_object').start()
        # We don't use real models as per mocks above. We also need to mock-out
        # methods that work with real data types
        mock.patch(
            'neutron.objects.base.NeutronDbObject.modify_fields_from_db'
        ).start()

        cfg.CONF.set_override("core_plugin", DB_PLUGIN_KLASS)
        cfg.CONF.set_override("service_plugins", ["router",
                                                  "conntrack_helper"])
        manager.init()
        # TODO(hjensas): Add CONNTRACKHELPER to neutron-lib Well-known
        #  service type constants.
        self.cth_plugin = directory.get_plugin("CONNTRACKHELPER")
        self.ctxt = context.Context('admin', 'fake_tenant')
        mock.patch.object(self.ctxt.session, 'refresh').start()
        mock.patch.object(self.ctxt.session, 'expunge').start()

    @mock.patch.object(resources_rpc.ResourcesPushRpcApi, 'push')
    @mock.patch.object(cth_plugin.Plugin, 'get_router')
    @mock.patch('neutron.objects.conntrack_helper.ConntrackHelper')
    def test_create_conntrack_helper(self, mock_conntrack_helper,
                                     mock_get_router, mock_push_api):
        cth_input = {
            'conntrack_helper': {
                'conntrack_helper': {
                    'protocol': 'udp',
                    'port': 69,
                    'helper': 'tftp'}
            }
        }
        cth_obj = mock.Mock()
        cth_obj.helper = 'tftp'
        cth_obj.protocol = 'udp'
        cth_obj.port = 69
        router_obj = mock.Mock()
        router_obj.id = 'faker-router-id'
        mock_get_router.return_value = router_obj
        mock_conntrack_helper.return_value = cth_obj
        self.cth_plugin.create_router_conntrack_helper(
            self.ctxt, router_obj.id, **cth_input)
        mock_conntrack_helper.assert_called_once_with(
            self.ctxt, **cth_input['conntrack_helper']['conntrack_helper'])
        self.assertTrue(cth_obj.create.called)
        mock_push_api.assert_called_once_with(
            self.ctxt, mock.ANY, rpc_events.CREATED)

    @mock.patch.object(cth_plugin.Plugin, '_find_existing_conntrack_helper')
    @mock.patch.object(cth_plugin.Plugin, 'get_router')
    @mock.patch('neutron.objects.conntrack_helper.ConntrackHelper')
    def test_negative_create_conntrack_helper(self, mock_conntrack_helper,
                                              mock_get_router,
                                              mock_find_existing):
        cth_input = {
            'conntrack_helper': {
                'protocol': 'udp',
                'port': '69',
                'helper': 'tftp'}
        }
        cth_obj = mock.Mock()
        router_obj = mock.Mock()
        router_obj.id = 'faker-router-id'
        mock_get_router.return_value = router_obj
        mock_conntrack_helper.return_value = cth_obj
        cth_obj.create.side_effect = obj_exc.NeutronDbObjectDuplicateEntry(
            mock.Mock(), mock.Mock())
        mock_find_existing.return_value = ('cth_obj', 'conflict_param')
        self.assertRaises(
            lib_exc.BadRequest,
            self.cth_plugin.create_router_conntrack_helper,
            self.ctxt, router_obj.id, cth_input)

    @mock.patch.object(cth_plugin.Plugin, '_find_existing_conntrack_helper')
    @mock.patch.object(cth_plugin.Plugin, 'get_router')
    @mock.patch('neutron.objects.conntrack_helper.ConntrackHelper')
    def test_negative_create_helper_not_allowed(
            self, mock_conntrack_helper, mock_get_router,
            mock_find_existing):
        cth_input = {
            'conntrack_helper': {
                'protocol': 'udp',
                'port': 70,
                'helper': 'foo'}
        }
        cth_obj = mock.Mock()
        cth_obj.helper = cth_input['conntrack_helper']['helper']
        cth_obj.protocol = cth_input['conntrack_helper']['protocol']
        cth_obj.port = cth_input['conntrack_helper']['port']
        router_obj = mock.Mock()
        router_obj.id = 'faker-router-id'
        mock_get_router.return_value = router_obj
        mock_conntrack_helper.return_value = cth_obj
        self.assertRaises(
            cth_exc.ConntrackHelperNotAllowed,
            self.cth_plugin.create_router_conntrack_helper,
            self.ctxt, router_obj.id, cth_input)

    @mock.patch.object(cth_plugin.Plugin, '_find_existing_conntrack_helper')
    @mock.patch.object(cth_plugin.Plugin, 'get_router')
    @mock.patch('neutron.objects.conntrack_helper.ConntrackHelper')
    def test_negative_create_helper_invalid_proto_for_helper(
            self, mock_conntrack_helper, mock_get_router,
            mock_find_existing):
        cth_input = {
            'conntrack_helper': {
                'protocol': 'tcp',
                'port': 69,
                'helper': 'tftp'}
        }
        cth_obj = mock.Mock()
        cth_obj.helper = cth_input['conntrack_helper']['helper']
        cth_obj.protocol = cth_input['conntrack_helper']['protocol']
        cth_obj.port = cth_input['conntrack_helper']['port']
        router_obj = mock.Mock()
        router_obj.id = 'faker-router-id'
        mock_get_router.return_value = router_obj
        mock_conntrack_helper.return_value = cth_obj
        self.assertRaises(
            cth_exc.InvalidProtocolForHelper,
            self.cth_plugin.create_router_conntrack_helper,
            self.ctxt, router_obj.id, cth_input)

    @mock.patch.object(resources_rpc.ResourcesPushRpcApi, 'push')
    @mock.patch.object(conntrack_helper.ConntrackHelper, 'get_object')
    def test_update_conntrack_helper(self, mock_cth_get_object, mock_rpc_push):
        cth_input = {
            'conntrack_helper': {
                'conntrack_helper': {
                    'protocol': 'udp',
                    'port': 69,
                    'helper': 'tftp'}
            }
        }
        cth_obj = mock.Mock()
        cth_obj.helper = 'tftp'
        cth_obj.protocol = 'udp'
        mock_cth_get_object.return_value = cth_obj
        self.cth_plugin.update_router_conntrack_helper(
            self.ctxt, 'cth_id', mock.ANY, **cth_input)
        mock_cth_get_object.assert_called_once_with(self.ctxt, id='cth_id')
        self.assertTrue(cth_obj.update_fields)
        self.assertTrue(cth_obj.update)
        mock_rpc_push.assert_called_once_with(
            self.ctxt, mock.ANY, rpc_events.UPDATED)

    @mock.patch.object(conntrack_helper.ConntrackHelper, 'get_object')
    def test_negative_update_conntrack_helper(self, mock_cth_get_object):
        cth_input = {
            'conntrack_helper': {
                'conntrack_helper': {
                    'protocol': 'udp',
                    'port': 69,
                    'helper': 'tftp'}
            }
        }
        mock_cth_get_object.return_value = None
        self.assertRaises(
            cth_exc.ConntrackHelperNotFound,
            self.cth_plugin.update_router_conntrack_helper,
            self.ctxt, 'cth_id', mock.ANY, **cth_input)

    @mock.patch.object(conntrack_helper.ConntrackHelper, 'get_object')
    def test_get_conntrack_helper(self, get_object_mock):
        self.cth_plugin.get_router_conntrack_helper(
            self.ctxt, 'cth_id', mock.ANY, fields=None)
        get_object_mock.assert_called_once_with(self.ctxt, id='cth_id')

    @mock.patch.object(conntrack_helper.ConntrackHelper, 'get_object')
    def test_negative_get_conntrack_helper(self, get_object_mock):
        get_object_mock.return_value = None
        self.assertRaises(
            cth_exc.ConntrackHelperNotFound,
            self.cth_plugin.get_router_conntrack_helper,
            self.ctxt, 'cth_id', mock.ANY, fields=None)

    @mock.patch.object(conntrack_helper.ConntrackHelper, 'get_objects')
    def test_get_conntrack_helpers(self, get_objects_mock):
        self.cth_plugin.get_router_conntrack_helpers(self.ctxt)
        get_objects_mock.assert_called_once_with(self.ctxt, _pager=mock.ANY,
                                                 router_id=None)

    @mock.patch.object(resources_rpc.ResourcesPushRpcApi, 'push')
    @mock.patch.object(conntrack_helper.ConntrackHelper, 'get_object')
    def test_delete_conntrack_helper(self, get_object_mock, mock_rpc_push):
        cth_obj = mock.Mock(id='cth_id',
                            router_id='fake-router',
                            protocol='udp',
                            port=69,
                            helper='tftp')
        get_object_mock.return_value = cth_obj
        self.cth_plugin.delete_router_conntrack_helper(self.ctxt, 'cth_id',
                                                       mock.ANY)
        cth_obj.delete.assert_called()
        mock_rpc_push.assert_called_once_with(
            self.ctxt, mock.ANY, rpc_events.DELETED)

    @mock.patch.object(conntrack_helper.ConntrackHelper, 'get_object')
    def test_negative_delete_conntrack_helper(self, get_object_mock):
        get_object_mock.return_value = None
        self.assertRaises(cth_exc.ConntrackHelperNotFound,
                          self.cth_plugin.delete_router_conntrack_helper,
                          self.ctxt, 'cth_id', mock.ANY)
