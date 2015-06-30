# Copyright 2014 OneConvergence, Inc. All Rights Reserved.
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
#

"""Test Library for OneConvergencePlugin."""

import uuid

import mock
from oslo_config import cfg

from neutron import context
from neutron.extensions import portbindings
from neutron import manager
from neutron.plugins.oneconvergence import plugin as nvsd_plugin
from neutron.tests.unit import _test_extension_portbindings as test_bindings
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin
from neutron.tests.unit.extensions import test_l3

PLUGIN_NAME = 'neutron.plugins.oneconvergence.plugin.OneConvergencePluginV2'


class OneConvergencePluginV2TestCase(test_plugin.NeutronDbPluginV2TestCase):
    _plugin_name = PLUGIN_NAME

    def setUp(self):
        if 'v6' in self._testMethodName:
            self.skipTest("NVSD Plugin does not support IPV6.")

        def mocked_oneconvergence_init(self):
            def side_effect(*args, **kwargs):
                return {'id': str(uuid.uuid4())}

            self.nvsdlib = mock.Mock()
            self.nvsdlib.create_network.side_effect = side_effect

        with mock.patch.object(nvsd_plugin.OneConvergencePluginV2,
                               'oneconvergence_init',
                               new=mocked_oneconvergence_init):
            super(OneConvergencePluginV2TestCase,
                  self).setUp(self._plugin_name)


class TestOneConvergencePluginNetworksV2(test_plugin.TestNetworksV2,
                                         OneConvergencePluginV2TestCase):
    pass


class TestOneConvergencePluginSubnetsV2(test_plugin.TestSubnetsV2,
                                        OneConvergencePluginV2TestCase):
    pass


class TestOneConvergencePluginPortsV2(test_plugin.TestPortsV2,
                                      test_bindings.PortBindingsTestCase,
                                      OneConvergencePluginV2TestCase):
    VIF_TYPE = portbindings.VIF_TYPE_OVS

    def test_port_vif_details(self):
        plugin = manager.NeutronManager.get_plugin()
        with self.port(name='name') as port1:
            ctx = context.get_admin_context()
            port = plugin.get_port(ctx, port1['port']['id'])
            self.assertEqual(port['binding:vif_type'],
                             portbindings.VIF_TYPE_OVS)

    def test_ports_vif_details(self):
        cfg.CONF.set_default('allow_overlapping_ips', True)
        plugin = manager.NeutronManager.get_plugin()
        with self.port(), self.port():
            ctx = context.get_admin_context()
            ports = plugin.get_ports(ctx)
            self.assertEqual(len(ports), 2)
            for port in ports:
                self.assertEqual(port['binding:vif_type'],
                                 portbindings.VIF_TYPE_OVS)


class TestOneConvergenceBasicGet(test_plugin.TestBasicGet,
                                 OneConvergencePluginV2TestCase):
    pass


class TestOneConvergenceV2HTTPResponse(test_plugin.TestV2HTTPResponse,
                                       OneConvergencePluginV2TestCase):
    pass


class TestOneConvergenceL3NatTestCase(test_l3.L3NatDBIntTestCase):
    _plugin_name = PLUGIN_NAME

    def setUp(self):
        if 'v6' in self._testMethodName:
            self.skipTest("NVSD Plugin does not support IPV6.")

        def mocked_oneconvergence_init(self):
            def side_effect(*args, **kwargs):
                return {'id': str(uuid.uuid4())}

            self.nvsdlib = mock.Mock()
            self.nvsdlib.create_network.side_effect = side_effect

        ext_mgr = test_l3.L3TestExtensionManager()

        with mock.patch.object(nvsd_plugin.OneConvergencePluginV2,
                               'oneconvergence_init',
                               new=mocked_oneconvergence_init):
            super(TestOneConvergenceL3NatTestCase,
                  self).setUp(plugin=self._plugin_name, ext_mgr=ext_mgr)

    def test_floatingip_with_invalid_create_port(self):
        self._test_floatingip_with_invalid_create_port(self._plugin_name)
