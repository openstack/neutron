# Copyright (c) 2026 Red Hat Inc.
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

from neutron_lib import context
from neutron_lib.plugins import constants as plugin_const
from neutron_lib.plugins import directory
from neutron_lib.services.pvlan import constants as pvlan_const
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron import manager
from neutron.objects import pvlan as pvlan_objects
from neutron.services.pvlan import exceptions as pvlan_exc
from neutron.tests.unit import testlib_api


DB_PLUGIN_KLASS = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'
PVLAN_PLUGIN_KLASS = 'neutron.services.pvlan.pvlan_plugin.PVLANPlugin'


class TestPVLANPlugin(testlib_api.SqlTestCase):

    def setUp(self):
        super().setUp()
        self.setup_coreplugin(load_plugins=False)

        cfg.CONF.set_override("core_plugin", DB_PLUGIN_KLASS)
        cfg.CONF.set_override("service_plugins", [PVLAN_PLUGIN_KLASS])

        manager.init()
        self.plugin = directory.get_plugin(plugin_const.PVLAN)
        self.mock_driver = mock.Mock()
        self.plugin.register_driver(self.mock_driver)
        self.ctxt = context.Context('admin', 'fake_project')

    def _make_payload(self, resource_id, request_body=None,
                      network_id=None):
        payload = mock.Mock()
        payload.context = mock.Mock()
        payload.context.session = mock.Mock()
        payload.resource_id = resource_id
        payload.request_body = request_body or {}
        if network_id:
            payload.metadata = {'network_id': network_id}
        return payload


class TestPVLANPluginMeta(TestPVLANPlugin):

    def test_get_plugin_type(self):
        self.assertEqual(plugin_const.PVLAN,
                         self.plugin.get_plugin_type())

    def test_get_plugin_description(self):
        self.assertEqual("PVLAN Service Plugin",
                         self.plugin.get_plugin_description())


class TestExtendNetworkDict(TestPVLANPlugin):

    def test_extend_network_with_pvlan_enabled(self):
        network_db = mock.Mock()
        network_db.pvlan = mock.Mock()
        network_db.pvlan.pvlan = True
        result = {}
        self.plugin._extend_network_dict_pvlan(result, network_db)
        self.assertTrue(result[pvlan_const.PVLAN])

    def test_extend_network_with_pvlan_disabled(self):
        network_db = mock.Mock()
        network_db.pvlan = mock.Mock()
        network_db.pvlan.pvlan = False
        result = {}
        self.plugin._extend_network_dict_pvlan(result, network_db)
        self.assertFalse(result[pvlan_const.PVLAN])

    def test_extend_network_without_pvlan_attr(self):
        network_db = mock.Mock(spec=[])
        result = {}
        self.plugin._extend_network_dict_pvlan(result, network_db)
        self.assertFalse(result[pvlan_const.PVLAN])

    def test_extend_network_with_pvlan_none(self):
        network_db = mock.Mock()
        network_db.pvlan = None
        result = {}
        self.plugin._extend_network_dict_pvlan(result, network_db)
        self.assertFalse(result[pvlan_const.PVLAN])


class TestExtendPortDict(TestPVLANPlugin):

    def test_extend_port_with_pvlan(self):
        port_db = mock.Mock()
        port_db.pvlan = mock.Mock()
        port_db.pvlan.pvlan_type = pvlan_const.ISOLATED_TYPE
        port_db.pvlan.pvlan_community = None
        result = {}
        self.plugin._extend_port_dict_pvlan(result, port_db)
        self.assertEqual(pvlan_const.ISOLATED_TYPE,
                         result[pvlan_const.PVLAN_TYPE])
        self.assertIsNone(result[pvlan_const.PVLAN_COMMUNITY])

    def test_extend_port_with_community_pvlan(self):
        port_db = mock.Mock()
        port_db.pvlan = mock.Mock()
        port_db.pvlan.pvlan_type = pvlan_const.COMMUNITY_TYPE
        port_db.pvlan.pvlan_community = 'my_community'
        result = {}
        self.plugin._extend_port_dict_pvlan(result, port_db)
        self.assertEqual(pvlan_const.COMMUNITY_TYPE,
                         result[pvlan_const.PVLAN_TYPE])
        self.assertEqual('my_community',
                         result[pvlan_const.PVLAN_COMMUNITY])

    def test_extend_port_without_pvlan_attr(self):
        port_db = mock.Mock(spec=[])
        result = {}
        self.plugin._extend_port_dict_pvlan(result, port_db)
        self.assertIsNone(result[pvlan_const.PVLAN_TYPE])
        self.assertIsNone(result[pvlan_const.PVLAN_COMMUNITY])

    def test_extend_port_with_pvlan_none(self):
        port_db = mock.Mock()
        port_db.pvlan = None
        result = {}
        self.plugin._extend_port_dict_pvlan(result, port_db)
        self.assertIsNone(result[pvlan_const.PVLAN_TYPE])
        self.assertIsNone(result[pvlan_const.PVLAN_COMMUNITY])


class TestNetworkPVLAN(TestPVLANPlugin):

    def test_network_create_with_pvlan_enabled(self):
        network_id = uuidutils.generate_uuid()
        payload = self._make_payload(
            network_id,
            request_body={pvlan_const.PVLAN: True})

        network_data = mock.Mock()
        network_data.pvlan = None
        mock_cls = mock.Mock()
        with mock.patch('neutron.objects.network.Network.get_object',
                        return_value=network_data), \
                mock.patch.object(pvlan_objects, 'NetworkPVLAN', mock_cls):
            self.plugin.pvlan_network_update(
                'NETWORK', 'precommit_create', self.plugin, payload=payload)
            mock_cls.assert_called_once_with(
                payload.context, network_id=network_id, pvlan=True)
            mock_cls.return_value.create.assert_called_once()

    def test_network_create_with_pvlan_disabled(self):
        network_id = uuidutils.generate_uuid()
        payload = self._make_payload(
            network_id,
            request_body={pvlan_const.PVLAN: False})

        network_data = mock.Mock()
        network_data.pvlan = None
        mock_cls = mock.Mock()
        with mock.patch('neutron.objects.network.Network.get_object',
                        return_value=network_data), \
                mock.patch.object(pvlan_objects, 'NetworkPVLAN', mock_cls):
            self.plugin.pvlan_network_update(
                'NETWORK', 'precommit_create', self.plugin, payload=payload)
            mock_cls.assert_called_once_with(
                payload.context, network_id=network_id, pvlan=False)
            mock_cls.return_value.create.assert_called_once()

    def test_network_create_without_pvlan_in_body(self):
        network_id = uuidutils.generate_uuid()
        payload = self._make_payload(
            network_id,
            request_body={'name': 'test-net'})

        with mock.patch('neutron.objects.network.Network.get_object') \
                as mock_net:
            self.plugin.pvlan_network_update(
                'NETWORK', 'precommit_create', self.plugin, payload=payload)
            mock_net.assert_not_called()

    def test_network_update_existing_pvlan(self):
        network_id = uuidutils.generate_uuid()
        payload = self._make_payload(
            network_id,
            request_body={pvlan_const.PVLAN: False})

        network_data = mock.Mock()
        network_data.pvlan = True
        mock_cls = mock.Mock()
        with mock.patch('neutron.objects.network.Network.get_object',
                        return_value=network_data), \
                mock.patch.object(pvlan_objects, 'NetworkPVLAN', mock_cls):
            self.plugin.pvlan_network_update(
                'NETWORK', 'precommit_update', self.plugin, payload=payload)
            mock_cls.update_objects.assert_called_once_with(
                payload.context, {'pvlan': False}, network_id=network_id)


class TestPortPVLAN(TestPVLANPlugin):

    def _mock_port_and_network(self, port_id, network_id,
                               pvlan_type=None, pvlan_community=None,
                               network_pvlan=None):
        port_data = mock.Mock()
        port_data.network_id = network_id
        port_data.pvlan_type = pvlan_type
        port_data.pvlan_community = pvlan_community
        port_data.device_owner = ''

        network_data = mock.Mock()
        network_data.pvlan = network_pvlan

        portpvlan_cls = mock.Mock()

        patches = {
            'port_obj': mock.patch(
                'neutron.objects.ports.Port.get_object',
                return_value=port_data),
            'net_obj': mock.patch(
                'neutron.objects.network.Network.get_object',
                return_value=network_data),
            'portpvlan_cls': mock.patch.object(
                pvlan_objects, 'PortPVLAN', portpvlan_cls),
        }
        return patches, portpvlan_cls

    def test_port_create_on_pvlan_network_defaults_to_promiscuous(self):
        port_id = uuidutils.generate_uuid()
        network_id = uuidutils.generate_uuid()
        payload = self._make_payload(port_id)

        mocks, pp_cls = self._mock_port_and_network(
            port_id, network_id, network_pvlan=True)
        with mocks['port_obj'], mocks['net_obj'], mocks['portpvlan_cls']:
            self.plugin._pvlan_port_update(payload=payload)
            pp_cls.assert_called_once_with(
                payload.context, port_id=port_id,
                pvlan_type=pvlan_const.PROMISCUOUS_TYPE,
                pvlan_community=None)
            pp_cls.return_value.create.assert_called_once()

    def test_port_create_with_isolated_type(self):
        port_id = uuidutils.generate_uuid()
        network_id = uuidutils.generate_uuid()
        payload = self._make_payload(
            port_id,
            request_body={pvlan_const.PVLAN_TYPE: pvlan_const.ISOLATED_TYPE})

        mocks, pp_cls = self._mock_port_and_network(
            port_id, network_id, network_pvlan=True)
        with mocks['port_obj'], mocks['net_obj'], mocks['portpvlan_cls']:
            self.plugin._pvlan_port_update(payload=payload)
            pp_cls.assert_called_once_with(
                payload.context, port_id=port_id,
                pvlan_type=pvlan_const.ISOLATED_TYPE,
                pvlan_community=None)
            pp_cls.return_value.create.assert_called_once()

    def test_port_create_with_community_type_and_name(self):
        port_id = uuidutils.generate_uuid()
        network_id = uuidutils.generate_uuid()
        payload = self._make_payload(
            port_id,
            request_body={
                pvlan_const.PVLAN_TYPE: pvlan_const.COMMUNITY_TYPE,
                pvlan_const.PVLAN_COMMUNITY: 'my_community'})

        mocks, pp_cls = self._mock_port_and_network(
            port_id, network_id, network_pvlan=True)
        with mocks['port_obj'], mocks['net_obj'], mocks['portpvlan_cls']:
            self.plugin._pvlan_port_update(payload=payload)
            pp_cls.assert_called_once_with(
                payload.context, port_id=port_id,
                pvlan_type=pvlan_const.COMMUNITY_TYPE,
                pvlan_community='my_community')
            pp_cls.return_value.create.assert_called_once()

    def test_port_create_community_type_without_name_raises(self):
        port_id = uuidutils.generate_uuid()
        network_id = uuidutils.generate_uuid()
        payload = self._make_payload(
            port_id,
            request_body={
                pvlan_const.PVLAN_TYPE: pvlan_const.COMMUNITY_TYPE})

        mocks, _ = self._mock_port_and_network(
            port_id, network_id, network_pvlan=True)
        with mocks['port_obj'], mocks['net_obj'], mocks['portpvlan_cls']:
            self.assertRaises(
                pvlan_exc.PVLANCommunityNameRequired,
                self.plugin._pvlan_port_update,
                payload=payload)

    def test_port_create_community_name_with_wrong_type_raises(self):
        port_id = uuidutils.generate_uuid()
        network_id = uuidutils.generate_uuid()
        payload = self._make_payload(
            port_id,
            request_body={
                pvlan_const.PVLAN_TYPE: pvlan_const.ISOLATED_TYPE,
                pvlan_const.PVLAN_COMMUNITY: 'my_community'})

        mocks, _ = self._mock_port_and_network(
            port_id, network_id, network_pvlan=True)
        with mocks['port_obj'], mocks['net_obj'], mocks['portpvlan_cls']:
            self.assertRaises(
                pvlan_exc.PVLANCannotSetCommunityName,
                self.plugin._pvlan_port_update,
                payload=payload)

    def test_port_create_pvlan_type_on_non_pvlan_network_raises(self):
        port_id = uuidutils.generate_uuid()
        network_id = uuidutils.generate_uuid()
        payload = self._make_payload(
            port_id,
            request_body={
                pvlan_const.PVLAN_TYPE: pvlan_const.ISOLATED_TYPE})

        mocks, _ = self._mock_port_and_network(
            port_id, network_id, network_pvlan=False)
        with mocks['port_obj'], mocks['net_obj'], mocks['portpvlan_cls']:
            self.assertRaises(
                pvlan_exc.PVLANNotEnabledOnNetwork,
                self.plugin._pvlan_port_update,
                payload=payload)

    def test_port_create_pvlan_type_on_network_without_pvlan_entry_raises(
            self):
        port_id = uuidutils.generate_uuid()
        network_id = uuidutils.generate_uuid()
        payload = self._make_payload(
            port_id,
            request_body={
                pvlan_const.PVLAN_TYPE: pvlan_const.PROMISCUOUS_TYPE})

        mocks, _ = self._mock_port_and_network(
            port_id, network_id, network_pvlan=None)
        with mocks['port_obj'], mocks['net_obj'], mocks['portpvlan_cls']:
            self.assertRaises(
                pvlan_exc.PVLANNotEnabledOnNetwork,
                self.plugin._pvlan_port_update,
                payload=payload)

    def test_port_create_on_non_pvlan_network_no_pvlan_attrs_returns(self):
        port_id = uuidutils.generate_uuid()
        network_id = uuidutils.generate_uuid()
        payload = self._make_payload(port_id)

        mocks, pp_cls = self._mock_port_and_network(
            port_id, network_id, network_pvlan=False)
        with mocks['port_obj'], mocks['net_obj'], mocks['portpvlan_cls']:
            self.plugin._pvlan_port_update(payload=payload)
            pp_cls.assert_not_called()

    def test_port_update_existing_pvlan(self):
        port_id = uuidutils.generate_uuid()
        network_id = uuidutils.generate_uuid()
        payload = self._make_payload(
            port_id,
            request_body={pvlan_const.PVLAN_TYPE: pvlan_const.ISOLATED_TYPE})

        mocks, pp_cls = self._mock_port_and_network(
            port_id, network_id,
            pvlan_type=pvlan_const.PROMISCUOUS_TYPE,
            network_pvlan=True)
        with mocks['port_obj'], mocks['net_obj'], mocks['portpvlan_cls']:
            self.plugin._pvlan_port_update(payload=payload)
            pp_cls.update_objects.assert_called_once_with(
                payload.context,
                {'pvlan_type': pvlan_const.ISOLATED_TYPE,
                 'pvlan_community': None},
                port_id=port_id)

    def test_port_update_no_pvlan_attrs_in_request_keeps_existing(self):
        port_id = uuidutils.generate_uuid()
        network_id = uuidutils.generate_uuid()
        payload = self._make_payload(
            port_id,
            request_body={'name': 'updated-port'})

        mocks, pp_cls = self._mock_port_and_network(
            port_id, network_id,
            pvlan_type=pvlan_const.ISOLATED_TYPE,
            network_pvlan=True)
        with mocks['port_obj'], mocks['net_obj'], mocks['portpvlan_cls']:
            self.plugin._pvlan_port_update(payload=payload)
            pp_cls.update_objects.assert_called_once_with(
                payload.context,
                {'pvlan_type': pvlan_const.ISOLATED_TYPE,
                 'pvlan_community': None},
                port_id=port_id)

    def test_port_update_community_name_change(self):
        port_id = uuidutils.generate_uuid()
        network_id = uuidutils.generate_uuid()
        payload = self._make_payload(
            port_id,
            request_body={
                pvlan_const.PVLAN_TYPE: pvlan_const.COMMUNITY_TYPE,
                pvlan_const.PVLAN_COMMUNITY: 'new_comm'})

        mocks, pp_cls = self._mock_port_and_network(
            port_id, network_id,
            pvlan_type=pvlan_const.COMMUNITY_TYPE,
            pvlan_community='old_comm',
            network_pvlan=True)
        with mocks['port_obj'], mocks['net_obj'], mocks['portpvlan_cls']:
            self.plugin._pvlan_port_update(payload=payload)
            pp_cls.update_objects.assert_called_once_with(
                payload.context,
                {'pvlan_type': pvlan_const.COMMUNITY_TYPE,
                 'pvlan_community': 'new_comm'},
                port_id=port_id)
