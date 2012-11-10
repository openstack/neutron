# Copyright (c) 2012 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import contextlib

from quantum import context
from quantum.extensions import portbindings
from quantum.manager import QuantumManager
from quantum.openstack.common import cfg
from quantum.tests.unit import test_db_plugin as test_plugin


class LinuxBridgePluginV2TestCase(test_plugin.QuantumDbPluginV2TestCase):

    _plugin_name = ('quantum.plugins.linuxbridge.'
                    'lb_quantum_plugin.LinuxBridgePluginV2')

    def setUp(self):
        super(LinuxBridgePluginV2TestCase, self).setUp(self._plugin_name)


class TestLinuxBridgeBasicGet(test_plugin.TestBasicGet,
                              LinuxBridgePluginV2TestCase):
    pass


class TestLinuxBridgeV2HTTPResponse(test_plugin.TestV2HTTPResponse,
                                    LinuxBridgePluginV2TestCase):
    pass


class TestLinuxBridgePortsV2(test_plugin.TestPortsV2,
                             LinuxBridgePluginV2TestCase):
    def test_port_vif_details(self):
        plugin = QuantumManager.get_plugin()
        with self.port(name='name') as port:
            port_id = port['port']['id']
            self.assertEqual(port['port']['binding:vif_type'],
                             portbindings.VIF_TYPE_BRIDGE)
            # By default user is admin - now test non admin user
            ctx = context.Context(user_id=None,
                                  tenant_id=self._tenant_id,
                                  is_admin=False,
                                  read_deleted="no")
            non_admin_port = plugin.get_port(ctx, port_id)
            self.assertTrue('status' in non_admin_port)
            self.assertFalse('binding:vif_type' in non_admin_port)

    def test_ports_vif_details(self):
        cfg.CONF.set_default('allow_overlapping_ips', True)
        plugin = QuantumManager.get_plugin()
        with contextlib.nested(self.port(), self.port()) as (port1, port2):
            ctx = context.get_admin_context()
            ports = plugin.get_ports(ctx)
            self.assertEqual(len(ports), 2)
            for port in ports:
                self.assertEqual(port['binding:vif_type'],
                                 portbindings.VIF_TYPE_BRIDGE)
            # By default user is admin - now test non admin user
            ctx = context.Context(user_id=None,
                                  tenant_id=self._tenant_id,
                                  is_admin=False,
                                  read_deleted="no")
            ports = plugin.get_ports(ctx)
            self.assertEqual(len(ports), 2)
            for non_admin_port in ports:
                self.assertTrue('status' in non_admin_port)
                self.assertFalse('binding:vif_type' in non_admin_port)


class TestLinuxBridgeNetworksV2(test_plugin.TestNetworksV2,
                                LinuxBridgePluginV2TestCase):
    pass
