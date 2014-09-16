# Copyright (C) 2012 Midokura Japan K.K.
# Copyright (C) 2013 Midokura PTE LTD
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

import mock
import os
import sys

import neutron.common.test_lib as test_lib
from neutron.extensions import portbindings
from neutron.tests.unit import _test_extension_portbindings as test_bindings
import neutron.tests.unit.midonet.mock_lib as mock_lib
import neutron.tests.unit.test_db_plugin as test_plugin
import neutron.tests.unit.test_extension_security_group as sg
import neutron.tests.unit.test_l3_plugin as test_l3_plugin

MIDOKURA_PKG_PATH = "neutron.plugins.midonet.plugin"
MIDONET_PLUGIN_NAME = ('%s.MidonetPluginV2' % MIDOKURA_PKG_PATH)


class MidonetPluginV2TestCase(test_plugin.NeutronDbPluginV2TestCase):

    def setUp(self,
              plugin=MIDONET_PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        self.mock_api = mock.patch(
            'neutron.plugins.midonet.midonet_lib.MidoClient')
        etc_path = os.path.join(os.path.dirname(__file__), 'etc')
        test_lib.test_config['config_files'] = [os.path.join(
            etc_path, 'midonet.ini.test')]

        p = mock.patch.dict(sys.modules, {'midonetclient': mock.Mock()})
        p.start()
        # dict patches must be explicitly stopped
        self.addCleanup(p.stop)
        self.instance = self.mock_api.start()
        mock_cfg = mock_lib.MidonetLibMockConfig(self.instance.return_value)
        mock_cfg.setup()

        self.midoclient_mock = mock.MagicMock()
        self.midoclient_mock.midonetclient.neutron.client.return_value = True
        modules = {
            'midonetclient': self.midoclient_mock,
            'midonetclient.neutron': self.midoclient_mock.neutron,
            'midonetclient.neutron.client': self.midoclient_mock.client,
        }

        self.module_patcher = mock.patch.dict('sys.modules', modules)
        self.module_patcher.start()
        self.addCleanup(self.module_patcher.stop)

        # import midonetclient here because it needs proper mock objects to be
        # assigned to this module first.  'midoclient_mock' object is the
        # mock object used for this module.
        from midonetclient.neutron.client import MidonetClient
        client_class = MidonetClient
        self.mock_class = client_class()

        super(MidonetPluginV2TestCase, self).setUp(plugin=plugin)


class TestMidonetNetworksV2(test_plugin.TestNetworksV2,
                            MidonetPluginV2TestCase):

    pass


class TestMidonetL3NatTestCase(MidonetPluginV2TestCase,
                               test_l3_plugin.L3NatDBIntTestCase):
    def setUp(self,
              plugin=MIDONET_PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        super(TestMidonetL3NatTestCase, self).setUp(plugin=plugin,
                                                    ext_mgr=None,
                                                    service_plugins=None)

    def test_floatingip_with_invalid_create_port(self):
        self._test_floatingip_with_invalid_create_port(MIDONET_PLUGIN_NAME)

    def test_floatingip_assoc_no_port(self):
        with self.subnet(cidr='200.0.0.0/24') as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            res = super(TestMidonetL3NatTestCase, self)._create_floatingip(
                self.fmt, public_sub['subnet']['network_id'])
            # Cleanup
            floatingip = self.deserialize(self.fmt, res)
            self._delete('floatingips', floatingip['floatingip']['id'])
        self.assertFalse(self.instance.return_value.add_static_nat.called)

    def test_floatingip_assoc_with_port(self):
        with self.subnet(cidr='200.0.0.0/24') as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            with self.port() as private_port:
                with self.router() as r:
                    # We need to hook up the private subnet to the external
                    # network in order to associate the fip.
                    sid = private_port['port']['fixed_ips'][0]['subnet_id']
                    private_sub = {'subnet': {'id': sid}}
                    self._add_external_gateway_to_router(
                        r['router']['id'],
                        public_sub['subnet']['network_id'])

                    # Check that get_link_port was called - if not, Source NAT
                    # will not be set up correctly on the MidoNet side
                    self.assertTrue(
                        self.instance.return_value.get_link_port.called)

                    self._router_interface_action('add', r['router']['id'],
                                                  private_sub['subnet']['id'],
                                                  None)

                    # Create the fip.
                    res = super(TestMidonetL3NatTestCase,
                                self)._create_floatingip(
                                    self.fmt,
                                    public_sub['subnet']['network_id'],
                                    port_id=private_port['port']['id'])

                    # Cleanup the resources used for the test
                    floatingip = self.deserialize(self.fmt, res)
                    self._delete('floatingips', floatingip['floatingip']['id'])
                    self._remove_external_gateway_from_router(
                        r['router']['id'],
                        public_sub['subnet']['network_id'])
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  private_sub['subnet']['id'],
                                                  None)
        self.assertTrue(self.instance.return_value.add_static_nat.called)

    def test_delete_ext_net_with_disassociated_floating_ips(self):
        pass


class TestMidonetSecurityGroupsTestCase(sg.SecurityGroupDBTestCase):

    _plugin_name = ('%s.MidonetPluginV2' % MIDOKURA_PKG_PATH)

    def setUp(self):
        self.mock_api = mock.patch(
            'neutron.plugins.midonet.midonet_lib.MidoClient')
        etc_path = os.path.join(os.path.dirname(__file__), 'etc')
        test_lib.test_config['config_files'] = [os.path.join(
            etc_path, 'midonet.ini.test')]

        self.instance = self.mock_api.start()
        mock_cfg = mock_lib.MidonetLibMockConfig(self.instance.return_value)
        mock_cfg.setup()
        p = mock.patch.dict(sys.modules, {'midonetclient': mock.Mock()})
        p.start()
        # dict patches must be explicitly stopped
        self.addCleanup(p.stop)
        self.midoclient_mock = mock.MagicMock()
        self.midoclient_mock.midonetclient.neutron.client.return_value = True
        modules = {
            'midonetclient': self.midoclient_mock,
            'midonetclient.neutron': self.midoclient_mock.neutron,
            'midonetclient.neutron.client': self.midoclient_mock.client,
        }

        self.module_patcher = mock.patch.dict('sys.modules', modules)
        self.module_patcher.start()
        self.addCleanup(self.module_patcher.stop)

        # import midonetclient here because it needs proper mock objects to be
        # assigned to this module first.  'midoclient_mock' object is the
        # mock object used for this module.
        from midonetclient.neutron.client import MidonetClient
        client_class = MidonetClient
        self.mock_class = client_class()

        super(TestMidonetSecurityGroupsTestCase, self).setUp(self._plugin_name)


class TestMidonetSecurityGroup(sg.TestSecurityGroups,
                               TestMidonetSecurityGroupsTestCase):

    pass


class TestMidonetSubnetsV2(test_plugin.TestSubnetsV2,
                           MidonetPluginV2TestCase):

    # IPv6 is not supported by MidoNet yet.  Ignore tests that attempt to
    # create IPv6 subnet.
    def test_create_subnet_inconsistent_ipv6_cidrv4(self):
        pass

    def test_create_subnet_inconsistent_ipv6_dns_v4(self):
        pass

    def test_create_subnet_with_v6_allocation_pool(self):
        pass

    def test_update_subnet_inconsistent_ipv6_gatewayv4(self):
        pass

    def test_update_subnet_inconsistent_ipv6_hostroute_dst_v4(self):
        pass

    def test_update_subnet_inconsistent_ipv6_hostroute_np_v4(self):
        pass

    def test_create_subnet_inconsistent_ipv6_gatewayv4(self):
        pass

    def test_create_subnet_dhcp_disabled(self):
        super(TestMidonetSubnetsV2, self)._test_create_subnet(
            enable_dhcp=False)
        self.assertFalse(self.instance.return_value.create_dhcp.called)


class TestMidonetPortsV2(test_plugin.TestPortsV2,
                         MidonetPluginV2TestCase):

    # IPv6 is not supported by MidoNet yet.  Ignore tests that attempt to
    # create IPv6 subnet.

    def test_requested_subnet_id_v4_and_v6(self):
        pass

    def test_vif_port_binding(self):
        with self.port(name='myname') as port:
            self.assertEqual('midonet', port['port']['binding:vif_type'])
            self.assertTrue(port['port']['admin_state_up'])


class TestMidonetPluginPortBinding(test_bindings.PortBindingsTestCase,
                                   MidonetPluginV2TestCase):

    VIF_TYPE = portbindings.VIF_TYPE_MIDONET
    HAS_PORT_FILTER = True

    def setUp(self):
        super(TestMidonetPluginPortBinding, self).setUp()
