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

from neutron_lib.callbacks import exceptions as c_exc
from neutron_lib.plugins import constants as plugin_consts
from neutron_lib.plugins import directory
from neutron_lib.services.pvlan import constants as pvlan_const
from oslo_config import cfg

from neutron.objects import pvlan as pvlan_objects
from neutron.services.pvlan import pvlan_plugin
from neutron.tests.functional import base as functional_base
from neutron.tests.unit.plugins.ml2 import base as ml2_test_base


class PVLANPluginTestCase(ml2_test_base.ML2TestFramework,
                          functional_base.BaseLoggingTestCase):

    def preSetUp(self):
        super().preSetUp()
        cfg.CONF.set_override('extension_drivers', ['port_security'],
                              group='ml2')

    def setUp(self):
        super().setUp()
        self.pvlan_plugin = pvlan_plugin.PVLANPlugin()
        self.mock_driver = mock.Mock()
        self.pvlan_plugin.register_driver(self.mock_driver)
        directory.add_plugin(plugin_consts.PVLAN, self.pvlan_plugin)

    def _create_network(self, name='test-net', pvlan=None,
                        port_security_enabled=None):
        net_data = {'name': name,
                    'admin_state_up': True,
                    'shared': False,
                    'project_id': self._project_id}
        if pvlan is not None:
            net_data[pvlan_const.PVLAN] = pvlan
        if port_security_enabled is not None:
            net_data['port_security_enabled'] = port_security_enabled
        return self.core_plugin.create_network(
            self.context, {'network': net_data})

    def _create_port(self, network_id, pvlan_type=None,
                     pvlan_community=None, port_security_enabled=None):
        port_data = {'network_id': network_id,
                     'name': '',
                     'admin_state_up': True,
                     'mac_address': '',
                     'fixed_ips': [],
                     'device_id': '',
                     'device_owner': '',
                     'project_id': self._project_id}
        if pvlan_type is not None:
            port_data[pvlan_const.PVLAN_TYPE] = pvlan_type
        if pvlan_community is not None:
            port_data[pvlan_const.PVLAN_COMMUNITY] = pvlan_community
        if port_security_enabled is not None:
            port_data['port_security_enabled'] = port_security_enabled
        return self.core_plugin.create_port(
            self.context, {'port': port_data})


class TestPVLANNetwork(PVLANPluginTestCase):

    def test_create_network_with_pvlan_enabled(self):
        net = self._create_network(pvlan=True)
        net = self.core_plugin.get_network(self.context, net['id'])
        self.assertTrue(net[pvlan_const.PVLAN])

    def test_create_network_without_pvlan(self):
        net = self._create_network()
        net = self.core_plugin.get_network(self.context, net['id'])
        self.assertFalse(net[pvlan_const.PVLAN])

    def test_update_network_enable_pvlan(self):
        net = self._create_network()
        self.core_plugin.update_network(
            self.context, net['id'],
            {'network': {pvlan_const.PVLAN: True}})
        net = self.core_plugin.get_network(self.context, net['id'])
        self.assertTrue(net[pvlan_const.PVLAN])

    def test_update_network_disable_pvlan(self):
        net = self._create_network(pvlan=True)
        self.core_plugin.update_network(
            self.context, net['id'],
            {'network': {pvlan_const.PVLAN: False}})
        net = self.core_plugin.get_network(self.context, net['id'])
        self.assertFalse(net[pvlan_const.PVLAN])


class TestPVLANPort(PVLANPluginTestCase):

    def test_create_port_on_pvlan_network_defaults_promiscuous(self):
        net = self._create_network(pvlan=True)
        port = self._create_port(net['id'])
        port = self.core_plugin.get_port(self.context, port['id'])
        self.assertEqual(pvlan_const.PROMISCUOUS_TYPE,
                         port[pvlan_const.PVLAN_TYPE])

    def test_create_port_with_isolated_type(self):
        net = self._create_network(pvlan=True)
        port = self._create_port(net['id'],
                                 pvlan_type=pvlan_const.ISOLATED_TYPE)
        port = self.core_plugin.get_port(self.context, port['id'])
        self.assertEqual(pvlan_const.ISOLATED_TYPE,
                         port[pvlan_const.PVLAN_TYPE])

    def test_create_port_with_community_type(self):
        net = self._create_network(pvlan=True)
        port = self._create_port(net['id'],
                                 pvlan_type=pvlan_const.COMMUNITY_TYPE,
                                 pvlan_community='test_community')
        port = self.core_plugin.get_port(self.context, port['id'])
        self.assertEqual(pvlan_const.COMMUNITY_TYPE,
                         port[pvlan_const.PVLAN_TYPE])
        self.assertEqual('test_community',
                         port[pvlan_const.PVLAN_COMMUNITY])

    def test_create_port_on_regular_network_no_pvlan_entry(self):
        net = self._create_network()
        port = self._create_port(net['id'])
        port = self.core_plugin.get_port(self.context, port['id'])
        self.assertIsNone(port[pvlan_const.PVLAN_TYPE])

    def test_create_port_pvlan_type_on_regular_network_raises(self):
        net = self._create_network()
        self.assertRaises(
            c_exc.CallbackFailure,
            self._create_port,
            net['id'],
            pvlan_type=pvlan_const.ISOLATED_TYPE)

    def test_create_port_community_without_name_raises(self):
        net = self._create_network(pvlan=True)
        self.assertRaises(
            c_exc.CallbackFailure,
            self._create_port,
            net['id'],
            pvlan_type=pvlan_const.COMMUNITY_TYPE)

    def test_create_port_community_name_wrong_type_raises(self):
        net = self._create_network(pvlan=True)
        self.assertRaises(
            c_exc.CallbackFailure,
            self._create_port,
            net['id'],
            pvlan_type=pvlan_const.ISOLATED_TYPE,
            pvlan_community='my_community')

    def test_update_port_pvlan_type(self):
        net = self._create_network(pvlan=True)
        port = self._create_port(net['id'])
        self.core_plugin.update_port(
            self.context, port['id'],
            {'port': {pvlan_const.PVLAN_TYPE: pvlan_const.ISOLATED_TYPE}})
        port = self.core_plugin.get_port(self.context, port['id'])
        self.assertEqual(pvlan_const.ISOLATED_TYPE,
                         port[pvlan_const.PVLAN_TYPE])

    def test_delete_network_cascades_pvlan(self):
        net = self._create_network(pvlan=True)
        self.core_plugin.delete_network(self.context, net['id'])
        self.assertIsNone(pvlan_objects.NetworkPVLAN.get_object(
            self.context, network_id=net['id']))

    def test_delete_port_cascades_pvlan(self):
        net = self._create_network(pvlan=True)
        port = self._create_port(net['id'])
        self.core_plugin.delete_port(self.context, port['id'])
        self.assertIsNone(pvlan_objects.PortPVLAN.get_object(
            self.context, port_id=port['id']))

    def test_enable_pvlan_on_network_updates_existing_ports(self):
        net = self._create_network()
        port = self._create_port(net['id'])
        port = self.core_plugin.get_port(self.context, port['id'])
        self.assertIsNone(port[pvlan_const.PVLAN_TYPE])

        self.core_plugin.update_network(
            self.context, net['id'],
            {'network': {pvlan_const.PVLAN: True}})
        port = self.core_plugin.get_port(self.context, port['id'])
        self.assertEqual(pvlan_const.PROMISCUOUS_TYPE,
                         port[pvlan_const.PVLAN_TYPE])

    def test_create_port_on_pvlan_network_port_security_disabled_raises(self):
        net = self._create_network(pvlan=True)
        self.assertRaises(
            c_exc.CallbackFailure,
            self._create_port,
            net['id'],
            port_security_enabled=False)

    def test_create_port_on_network_with_network_security_disabled_raises(
            self):
        net = self._create_network(pvlan=True)
        self.core_plugin.update_network(
            self.context, net['id'],
            {'network': {'port_security_enabled': False}})
        self.assertRaises(
            c_exc.CallbackFailure,
            self._create_port,
            net['id'])

    def test_disable_pvlan_on_network_clears_port_pvlan(self):
        net = self._create_network(pvlan=True)
        port = self._create_port(net['id'],
                                 pvlan_type=pvlan_const.ISOLATED_TYPE)
        port = self.core_plugin.get_port(self.context, port['id'])
        self.assertEqual(pvlan_const.ISOLATED_TYPE,
                         port[pvlan_const.PVLAN_TYPE])

        self.core_plugin.update_network(
            self.context, net['id'],
            {'network': {pvlan_const.PVLAN: False}})
        port = self.core_plugin.get_port(self.context, port['id'])
        self.assertIsNone(port[pvlan_const.PVLAN_TYPE])
