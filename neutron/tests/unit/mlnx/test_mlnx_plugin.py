# Copyright (c) 2013 OpenStack Foundation
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
from webob import exc

from neutron.extensions import portbindings
from neutron.plugins.mlnx.common import constants
from neutron.tests.unit import _test_extension_portbindings as test_bindings
from neutron.tests.unit import test_db_plugin as test_plugin
from neutron.tests.unit import test_security_groups_rpc as test_sg_rpc


PLUGIN_NAME = ('neutron.plugins.mlnx.mlnx_plugin.MellanoxEswitchPlugin')


class MlnxPluginV2TestCase(test_plugin.NeutronDbPluginV2TestCase):
    _plugin_name = PLUGIN_NAME

    def setUp(self):
        super(MlnxPluginV2TestCase, self).setUp(self._plugin_name)
        self.port_create_status = 'DOWN'


class TestMlnxBasicGet(test_plugin.TestBasicGet, MlnxPluginV2TestCase):
    pass


class TestMlnxV2HTTPResponse(test_plugin.TestV2HTTPResponse,
                             MlnxPluginV2TestCase):
    pass


class TestMlnxPortsV2(test_plugin.TestPortsV2,
                      MlnxPluginV2TestCase):
    pass


class TestMlnxNetworksV2(test_plugin.TestNetworksV2, MlnxPluginV2TestCase):
    pass


class TestMlnxPortBinding(MlnxPluginV2TestCase,
                          test_bindings.PortBindingsTestCase):
    VIF_TYPE = constants.VIF_TYPE_DIRECT
    ENABLE_SG = False
    HAS_PORT_FILTER = False

    def setUp(self, firewall_driver=None):
        cfg.CONF.set_override(
            'enable_security_group', self.ENABLE_SG,
            group='SECURITYGROUP')
        super(TestMlnxPortBinding, self).setUp()

    def _check_default_port_binding_profole(self, port,
                                            expected_vif_type=None):
        if expected_vif_type is None:
            expected_vif_type = constants.VIF_TYPE_DIRECT
        p = port['port']
        self.assertIn('id', p)
        self.assertEqual(expected_vif_type, p[portbindings.VIF_TYPE])
        self.assertEqual({'physical_network': 'default'},
                         p[portbindings.PROFILE])

    def test_create_port_no_binding_profile(self):
        with self.port() as port:
            self._check_default_port_binding_profole(port)

    def test_create_port_binding_profile_none(self):
        profile_arg = {portbindings.PROFILE: None}
        with self.port(arg_list=(portbindings.PROFILE,),
                       **profile_arg) as port:
            self._check_default_port_binding_profole(port)

    def test_create_port_binding_profile_vif_type(self):
        for vif_type in [constants.VIF_TYPE_HOSTDEV,
                         constants.VIF_TYPE_DIRECT]:
            profile_arg = {portbindings.PROFILE:
                           {constants.VNIC_TYPE: vif_type}}
            with self.port(arg_list=(portbindings.PROFILE,),
                           **profile_arg) as port:
                self._check_default_port_binding_profole(
                    port, expected_vif_type=vif_type)
                self._delete('ports', port['port']['id'])
                self._delete('networks', port['port']['network_id'])

    def test_create_port_binding_profile_with_empty_dict(self):
        profile_arg = {portbindings.PROFILE: {}}
        try:
            with self.port(arg_list=(portbindings.PROFILE,),
                           expected_res_status=400, **profile_arg):
                pass
        except exc.HTTPClientError:
            pass


class TestMlnxPortBindingNoSG(TestMlnxPortBinding):
    HAS_PORT_FILTER = False
    ENABLE_SG = False
    FIREWALL_DRIVER = test_sg_rpc.FIREWALL_NOOP_DRIVER


class TestMlnxPortBindingHost(
    MlnxPluginV2TestCase,
    test_bindings.PortBindingsHostTestCaseMixin):
    pass
