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


from neutron.db.models import l3
from neutron.services.ovn_l3.service_providers import user_defined
from neutron.tests.unit import testlib_api


DB_PLUGIN_KLASS = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'


class TestUserDefined(testlib_api.SqlTestCase):

    def setUp(self):
        super(TestUserDefined, self).setUp()
        self.setup_coreplugin(DB_PLUGIN_KLASS)
        self.fake_l3 = mock.MagicMock()
        self.fake_l3._make_router_interface_info = mock.MagicMock(
            return_value='router_interface_info')
        self.provider = user_defined.UserDefined(self.fake_l3)
        self.context = 'fake-context'
        self.router = l3.Router(id='fake-uuid',
                                flavor_id='fake-uuid')
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
