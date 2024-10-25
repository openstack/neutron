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

from unittest import mock

import ddt
from neutron_lib.api.definitions import external_net as enet_apidef
from neutron_lib.api.definitions import floatingip_pools as apidef
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib import constants as lib_const
from neutron_lib import context
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.db import l3_fip_pools_db
from neutron.extensions import l3
from neutron.objects import network as net_obj
from neutron.objects import subnet as subnet_obj
from neutron.tests.unit.extensions import test_l3


class FloatingIPPoolsTestExtensionManager:

    def get_resources(self):
        return l3.L3.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class TestFloatingIPPoolsIntPlugin(
        test_l3.TestL3NatIntPlugin,
        l3_fip_pools_db.FloatingIPPoolsDbMixin):
    supported_extension_aliases = [enet_apidef.ALIAS, l3_apidef.ALIAS,
                                   apidef.ALIAS]


class TestFloatingIPPoolsL3NatServicePlugin(
        test_l3.TestL3NatServicePlugin,
        l3_fip_pools_db.FloatingIPPoolsDbMixin):
    supported_extension_aliases = [l3_apidef.ALIAS, apidef.ALIAS]


@ddt.ddt
class FloatingIPPoolsDBTestCaseBase(test_l3.L3NatTestCaseMixin):

    def test_get_floatingip_pools_ipv4(self):
        self._test_get_floatingip_pools(lib_const.IP_VERSION_4, False)

    @ddt.data(True, False)
    def test_get_floatingip_pools_ipv6(self, fake_is_v6_supported):
        self._test_get_floatingip_pools(lib_const.IP_VERSION_6,
                                        fake_is_v6_supported)

    def _test_get_floatingip_pools(self, ip_version, is_v6_supported):
        fake_network_id = uuidutils.generate_uuid()
        fake_subnet_id = uuidutils.generate_uuid()
        fake_ext_network = mock.Mock(network_id=fake_network_id)
        if ip_version == lib_const.IP_VERSION_4:
            fake_cidr = '10.0.0.0/24'
        else:
            fake_cidr = 'fe80:cafe::/64'
        fake_subnet = mock.Mock(id=fake_subnet_id,
                                network_id=fake_network_id,
                                cidr=fake_cidr,
                                ip_version=ip_version,
                                tenant_id='fake_tenant',
                                project_id='fake_tenant')
        fake_subnet.name = 'fake_subnet'
        self.plugin._is_v6_supported = is_v6_supported
        with mock.patch.object(
            subnet_obj.Subnet, 'get_objects',
            return_value=[fake_subnet]
        ) as mock_subnet_get_objects, mock.patch.object(
            net_obj.ExternalNetwork, 'get_objects',
            return_value=[fake_ext_network]
        ) as mock_extnet_get_objects, mock.patch.object(
            self.ctxt, 'elevated',
            return_value=self.admin_ctxt
        ) as mock_context_elevated:
            fip_pools = self.plugin.get_floatingip_pools(self.ctxt)

        expected_fip_pools = []
        if ip_version == lib_const.IP_VERSION_4 or is_v6_supported:
            expected_fip_pools = [{'cidr': fake_cidr,
                                   'subnet_id': fake_subnet_id,
                                   'subnet_name': 'fake_subnet',
                                   'network_id': fake_network_id,
                                   'project_id': 'fake_tenant',
                                   'tenant_id': 'fake_tenant'}]
        self.assertEqual(expected_fip_pools, fip_pools)
        mock_subnet_get_objects.assert_called_once_with(
            self.admin_ctxt, _pager=mock.ANY, network_id=[fake_network_id])
        mock_extnet_get_objects.assert_called_once_with(self.ctxt)
        mock_context_elevated.assert_called_once_with()


class FloatingIPPoolsDBIntTestCase(test_l3.L3BaseForIntTests,
                                   FloatingIPPoolsDBTestCaseBase):

    def setUp(self, plugin=None):
        if not plugin:
            plugin = ('neutron.tests.unit.extensions.test_floatingip_pools.'
                      'TestFloatingIPPoolsIntPlugin')
        cfg.CONF.set_default('max_routes', 3)
        ext_mgr = FloatingIPPoolsTestExtensionManager()
        super(test_l3.L3BaseForIntTests, self).setUp(
            plugin=plugin,
            ext_mgr=ext_mgr)

        self.setup_notification_driver()
        self.ctxt = context.Context('fake_user', 'fake_tenant')
        self.admin_ctxt = self.ctxt.elevated()


class FloatingIPPoolsDBSepTestCase(test_l3.L3BaseForSepTests,
                                   FloatingIPPoolsDBTestCaseBase):

    def setUp(self):
        # the plugin without L3 support
        plugin = 'neutron.tests.unit.extensions.test_l3.TestNoL3NatPlugin'
        # the L3 service plugin
        l3_plugin = ('neutron.tests.unit.extensions.test_floatingip_pools.'
                     'TestFloatingIPPoolsL3NatServicePlugin')
        service_plugins = {'l3_plugin_name': l3_plugin}

        cfg.CONF.set_default('max_routes', 3)
        ext_mgr = FloatingIPPoolsTestExtensionManager()
        super(test_l3.L3BaseForSepTests, self).setUp(
            plugin=plugin,
            ext_mgr=ext_mgr,
            service_plugins=service_plugins)

        self.setup_notification_driver()
        self.plugin = directory.get_plugin(plugin_constants.L3)
        self.ctxt = context.Context('fake_user', 'fake_tenant')
        self.admin_ctxt = self.ctxt.elevated()
