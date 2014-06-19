# Copyright (c) 2012 OpenStack Foundation.
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

from oslo.config import cfg

from neutron import context
from neutron.extensions import portbindings
from neutron.extensions import securitygroup as ext_sg
from neutron.plugins.openvswitch import ovs_neutron_plugin
from neutron.tests.unit import _test_extension_portbindings as test_bindings
from neutron.tests.unit import test_db_plugin as test_plugin
from neutron.tests.unit import test_extension_allowedaddresspairs as test_pair
from neutron.tests.unit import test_security_groups_rpc as test_sg_rpc

import mock


class OpenvswitchPluginV2TestCase(test_plugin.NeutronDbPluginV2TestCase):

    _plugin_name = ('neutron.plugins.openvswitch.'
                    'ovs_neutron_plugin.OVSNeutronPluginV2')

    def setUp(self):
        super(OpenvswitchPluginV2TestCase, self).setUp(self._plugin_name)
        self.port_create_status = 'DOWN'


class TestOpenvswitchBasicGet(test_plugin.TestBasicGet,
                              OpenvswitchPluginV2TestCase):
    pass


class TestOpenvswitchV2HTTPResponse(test_plugin.TestV2HTTPResponse,
                                    OpenvswitchPluginV2TestCase):
    pass


class TestOpenvswitchPortsV2(test_plugin.TestPortsV2,
                             OpenvswitchPluginV2TestCase):

    def test_update_port_status_build(self):
        with self.port() as port:
            self.assertEqual(port['port']['status'], 'DOWN')
            self.assertEqual(self.port_create_status, 'DOWN')


class TestOpenvswitchNetworksV2(test_plugin.TestNetworksV2,
                                OpenvswitchPluginV2TestCase):
    pass


class TestOpenvswitchPortBinding(OpenvswitchPluginV2TestCase,
                                 test_bindings.PortBindingsTestCase):
    VIF_TYPE = portbindings.VIF_TYPE_OVS
    HAS_PORT_FILTER = True
    ENABLE_SG = True
    FIREWALL_DRIVER = test_sg_rpc.FIREWALL_HYBRID_DRIVER

    def setUp(self, firewall_driver=None):
        test_sg_rpc.set_firewall_driver(self.FIREWALL_DRIVER)
        cfg.CONF.set_override(
            'enable_security_group', self.ENABLE_SG,
            group='SECURITYGROUP')
        super(TestOpenvswitchPortBinding, self).setUp()


class TestOpenvswitchPortBindingNoSG(TestOpenvswitchPortBinding):
    HAS_PORT_FILTER = False
    ENABLE_SG = False
    FIREWALL_DRIVER = test_sg_rpc.FIREWALL_NOOP_DRIVER


class TestOpenvswitchPortBindingHost(
    OpenvswitchPluginV2TestCase,
    test_bindings.PortBindingsHostTestCaseMixin):
    pass


class TestOpenvswitchAllowedAddressPairs(OpenvswitchPluginV2TestCase,
                                         test_pair.TestAllowedAddressPairs):
    pass


class TestOpenvswitchUpdatePort(OpenvswitchPluginV2TestCase,
                                ovs_neutron_plugin.OVSNeutronPluginV2):

    def test_update_port_add_remove_security_group(self):
        get_port_func = (
            'neutron.db.db_base_plugin_v2.'
            'NeutronDbPluginV2.get_port'
        )
        with mock.patch(get_port_func) as mock_get_port:
            mock_get_port.return_value = {
                ext_sg.SECURITYGROUPS: ["sg1", "sg2"],
                "admin_state_up": True,
                "fixed_ips": "fake_ip",
                "network_id": "fake_id"}

            update_port_func = (
                'neutron.db.db_base_plugin_v2.'
                'NeutronDbPluginV2.update_port'
            )
            with mock.patch(update_port_func) as mock_update_port:
                mock_update_port.return_value = {
                    ext_sg.SECURITYGROUPS: ["sg2", "sg3"],
                    "admin_state_up": True,
                    "fixed_ips": "fake_ip",
                    "network_id": "fake_id"}

                fake_func = (
                    'neutron.plugins.openvswitch.'
                    'ovs_db_v2.get_network_binding'
                )
                with mock.patch(fake_func) as mock_func:
                    class MockBinding:
                        network_type = "fake"
                        segmentation_id = "fake"
                        physical_network = "fake"

                    mock_func.return_value = MockBinding()

                    ctx = context.Context('', 'somebody')
                    self.update_port(ctx, "id", {
                        "port": {
                            ext_sg.SECURITYGROUPS: [
                                "sg2", "sg3"]}})

                    sgmu = self.notifier.security_groups_member_updated
                    sgmu.assert_called_with(ctx, set(['sg1', 'sg3']))

    def setUp(self):
        super(TestOpenvswitchUpdatePort, self).setUp()
        self.update_security_group_on_port = mock.MagicMock(return_value=True)
        self._process_portbindings_create_and_update = mock.MagicMock(
            return_value=True)
        self._update_extra_dhcp_opts_on_port = mock.MagicMock(
            return_value=True)
        self.update_address_pairs_on_port = mock.MagicMock(
            return_value=True)

        class MockNotifier:
            def __init__(self):
                self.port_update = mock.MagicMock(return_value=True)
                self.security_groups_member_updated = mock.MagicMock(
                    return_value=True)

        self.notifier = MockNotifier()
