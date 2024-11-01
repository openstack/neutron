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
#

from unittest import mock

from neutron_lib.callbacks import events
from neutron_lib import constants as const
from oslo_utils import uuidutils

from neutron.db.models import l3
from neutron.db.models import l3_attrs
from neutron.objects import router as l3_obj
from neutron.services.ovn_l3.service_providers import user_defined
from neutron.tests.unit import testlib_api


DB_PLUGIN_KLASS = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'


class TestUserDefined(testlib_api.SqlTestCase):

    def setUp(self):
        super().setUp()
        self.setup_coreplugin(DB_PLUGIN_KLASS)
        self.fake_l3 = mock.MagicMock()
        self.fake_l3._make_router_interface_info = mock.MagicMock(
            return_value='router_interface_info')
        self.provider = user_defined.UserDefined(self.fake_l3)
        self.context = 'fake-context'
        self.router = l3.Router(id='fake-uuid',
                                flavor_id='fake-uuid')
        self.router['extra_attributes'] = l3_attrs.RouterExtraAttributes()
        self.fake_l3.get_router = mock.MagicMock(return_value=self.router)
        self.fip = {'router_id': 'fake-uuid'}
        mock_flavor_plugin = mock.MagicMock()
        mock_flavor_plugin.get_flavor = mock.MagicMock(
            return_value={'id': 'fake-uuid'})
        mock_flavor_plugin.get_flavor_next_provider = mock.MagicMock(
            return_value=[{'driver': self.provider._user_defined_provider}])
        self.provider._flavor_plugin_ref = mock_flavor_plugin

    def test__is_user_defined_provider(self):
        # test the positive case
        self.assertTrue(self.provider._is_user_defined_provider(
            self.context, self.router))

        # test the negative case
        self.provider._flavor_plugin_ref.get_flavor_next_provider = (
            mock.MagicMock(return_value=[{'driver': None}]))
        self.assertFalse(self.provider._is_user_defined_provider(
            self.context, self.router))

        # test flavor_id request not specified
        self.router.flavor_id = None
        self.assertFalse(self.provider._is_user_defined_provider(
            self.context, self.router))
        self.router.flavor_id = const.ATTR_NOT_SPECIFIED
        self.assertFalse(self.provider._is_user_defined_provider(
            self.context, self.router))

    def test_router_processing(self):
        with mock.patch.object(user_defined.LOG, 'debug') as log:
            payload = events.DBEventPayload(
                self.context,
                states=(self.router, self.router),
                resource_id=self.router['id'],
                metadata={'subnet_ids': ['subnet-id']})
            fl_plg = self.provider._flavor_plugin_ref
            methods = [self.provider._process_router_add_association,
                       self.provider._process_router_create,
                       self.provider._process_router_update,
                       self.provider._process_router_delete,
                       self.provider._process_remove_router_interface]
            for method in methods:
                method('resource', 'event', self, payload)
                fl_plg.get_flavor.assert_called_once()
                fl_plg.get_flavor_next_provider.assert_called_once()
                log.assert_called_once()
                fl_plg.get_flavor.reset_mock()
                fl_plg.get_flavor_next_provider.reset_mock()
                log.reset_mock()

    def test_add_router_interface(self):
        with mock.patch.object(user_defined.LOG, 'debug') as log:
            payload = events.DBEventPayload(
                self.context,
                states=(self.router, self.router),
                resource_id=self.router['id'],
                metadata={'subnet_ids': ['subnet-id'],
                          'port': {'tenant_id': 'tenant-id',
                                   'id': 'id',
                                   'network_id': 'network-id'},
                          'subnets': [{'id': 'id'}]})
            fl_plg = self.provider._flavor_plugin_ref
            l3_plg = self.fake_l3
            self.provider._process_add_router_interface('resource',
                                                        'event',
                                                        self,
                                                        payload)
            l3_plg._make_router_interface_info.assert_called_once()
            fl_plg.get_flavor.assert_called_once()
            fl_plg.get_flavor_next_provider.assert_called_once()
            log.assert_called_once()

    def test_floatingip_processing(self):
        # Test all the methods related to FIP processing
        with mock.patch.object(user_defined.LOG, 'debug') as log:
            payload = events.DBEventPayload(
                self.context,
                states=(self.fip, self.fip))
            fl_plg = self.provider._flavor_plugin_ref
            l3_plg = self.fake_l3
            methods = [self.provider._process_floatingip_create,
                       self.provider._process_floatingip_update,
                       self.provider._process_floatingip_delete,
                       self.provider._process_floatingip_status_update]
            for method in methods:
                method('resource', 'event', self, payload)
                l3_plg.get_router.assert_called_once()
                fl_plg.get_flavor.assert_called_once()
                fl_plg.get_flavor_next_provider.assert_called_once()
                log.assert_called_once()
                l3_plg.get_router.reset_mock()
                fl_plg.get_flavor.reset_mock()
                fl_plg.get_flavor_next_provider.reset_mock()
                log.reset_mock()

    def test__is_ha(self):
        # test the positive case
        router_req = {'id': 'fake-uuid',
                      'flavor_id': 'fake-uuid',
                      'ha': True}
        self.assertTrue(self.provider._is_ha(router_req))

        # test the negative case
        router_req['ha'] = False
        self.assertFalse(self.provider._is_ha(router_req))

    @mock.patch('neutron.db.l3_attrs_db.get_attr_info')
    def test__process_precommit_router_create(self, gai):
        gai.return_value = {'ha': {'default': False}}
        router_req = {'id': 'fake-uuid',
                      'flavor_id': 'fake-uuid',
                      'ha': True}
        payload = events.DBEventPayload(
            self.context,
            resource_id=self.router['id'],
            states=(router_req,),
            metadata={'router_db': self.router})
        self.assertFalse(self.router['extra_attributes'].ha)
        self.provider._process_precommit_router_create('resource', 'event',
                                                       self, payload)
        self.assertTrue(self.router['extra_attributes'].ha)


class TestUserDefinedNoLsp(testlib_api.SqlTestCase):

    def setUp(self):
        super().setUp()
        self.setup_coreplugin(DB_PLUGIN_KLASS)
        self.fake_l3 = mock.MagicMock()
        self.fake_l3._make_router_interface_info = mock.MagicMock(
            return_value='router_interface_info')
        self.provider = user_defined.UserDefinedNoLsp(self.fake_l3)
        self.context = mock.MagicMock()
        self.router = l3.Router(id='fake-uuid',
                                flavor_id='fake-uuid')
        mock_flavor_plugin = mock.MagicMock()
        mock_flavor_plugin.get_flavor = mock.MagicMock(
            return_value={'id': 'fake-uuid'})
        mock_flavor_plugin.get_flavor_next_provider = mock.MagicMock(
            return_value=[{'driver': self.provider._user_defined_provider}])
        self.provider._flavor_plugin_ref = mock_flavor_plugin

    @mock.patch.object(user_defined.LOG, 'debug')
    def test__add_router_interface(self, log_mock):
        payload = events.DBEventPayload(
            self.context,
            states=(self.router, self.router),
            resource_id=self.router['id'],
            metadata={'subnet_ids': ['subnet-id'],
                      'port': {'tenant_id': 'tenant-id',
                               'id': 'id',
                               'network_id': 'network-id'},
                      'subnets': [{'id': 'id'}]})
        fl_plg = self.provider._flavor_plugin_ref
        l3_plg = self.fake_l3
        self.provider._process_add_router_interface('resource',
                                                    'event',
                                                    self,
                                                    payload)
        l3_plg._make_router_interface_info.assert_called_once()
        fl_plg.get_flavor.assert_called_once()
        fl_plg.get_flavor_next_provider.assert_called_once()
        l3_plg._ovn_client.delete_port.assert_called_once()
        log_mock.assert_called_once()

    @mock.patch.object(l3_obj.RouterPort, 'get_objects')
    @mock.patch.object(l3_obj.Router, 'get_object')
    @mock.patch.object(user_defined.LOG, 'debug')
    def _test__process_before_remove_router_interface(self, port_exists,
                                                      log_mock, grouter_mock,
                                                      get_objects_mock):
        payload = events.DBEventPayload(
            self.context,
            resource_id=self.router['id'],
            metadata={'subnet_id': 'subnet-id'})
        grouter_mock.return_value = {'id': 'fake-uuid',
                                     'flavor_id': 'fake-uuid'}
        nbdb_idl_mock = mock.MagicMock()
        nbdb_idl_mock.lookup = mock.MagicMock()
        if port_exists:
            nbdb_idl_mock.lookup.return_value = 'a-port'
        else:
            nbdb_idl_mock.lookup.return_value = None
        self.fake_l3._ovn_client = mock.MagicMock()
        self.fake_l3._ovn_client._nb_idl = nbdb_idl_mock

        port_id = uuidutils.generate_uuid()
        other_port_id = uuidutils.generate_uuid()
        rp = l3_obj.RouterPort(
                self.context,
                port_id=port_id,
                router_id=uuidutils.generate_uuid(),
                port_type=const.DEVICE_OWNER_ROUTER_INTF)
        rp.create()
        other_rp = l3_obj.RouterPort(
                self.context,
                port_id=other_port_id,
                router_id=uuidutils.generate_uuid(),
                port_type=const.DEVICE_OWNER_ROUTER_INTF)
        other_rp.create()
        get_objects_mock.return_value = [rp, other_rp]

        gen_ports = (port for port in
                     [{'id': other_port_id,
                       'fixed_ips': [{'subnet_id': 'other-subnet-id'}],
                       'standard_attr_id': 'standard_attr_id'},
                      {'id': port_id,
                       'fixed_ips': [{'subnet_id': 'subnet-id'}],
                       'standard_attr_id': 'standard_attr_id'}])
        self.fake_l3._plugin = mock.MagicMock()
        self.fake_l3._plugin._make_port_dict = mock.MagicMock(
            side_effect=lambda p: next(gen_ports))

        self.provider._process_before_remove_router_interface('resource',
                                                              'event',
                                                              self,
                                                              payload)

        if port_exists:
            self.fake_l3._ovn_client.create_port.assert_not_called()
            log_mock.assert_not_called()
        else:
            self.fake_l3._ovn_client.create_port.assert_called_once()
            log_mock.assert_called_once()

    def test__process_before_remove_router_interface_port_exists(self):
        self._test__process_before_remove_router_interface(True)

    def test__process_before_remove_router_interface_port_doesnt_exist(self):
        self._test__process_before_remove_router_interface(False)
