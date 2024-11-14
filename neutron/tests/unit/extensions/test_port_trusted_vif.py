# Copyright (c) 2023 Red Hat, Inc.
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

import ddt
from neutron_lib.api.definitions import port_trusted_vif as apidef
from neutron_lib.api.definitions import portbindings
from neutron_lib import context
from oslo_config import cfg

from neutron.db import port_trusted_db
from neutron.plugins.ml2 import plugin
from neutron.tests.common import test_db_base_plugin_v2


class PortTrustedExtensionTestPlugin(
        plugin.Ml2Plugin,
        port_trusted_db.PortTrustedDbMixin):
    """Test plugin to mixin the port trusted extension."""

    supported_extension_aliases = [apidef.ALIAS, portbindings.ALIAS]


@ddt.ddt
class PortTrustedExtensionTestCase(
         test_db_base_plugin_v2.NeutronDbPluginV2TestCase):
    """Test API extension port-trusted-vif attributes."""

    def setUp(self, *args):
        plugin = ('neutron.tests.unit.extensions.test_port_trusted_vif.'
                  'PortTrustedExtensionTestPlugin')
        extension_drivers = ['port_trusted']
        cfg.CONF.set_override('extension_drivers', extension_drivers, 'ml2')
        super().setUp(plugin=plugin)
        self.ctx = context.get_admin_context()

    def _create_and_check_port_with_trusted_field(self, trusted):
        name = 'port-trusted-vif'
        keys = [('name', name),
                ('admin_state_up', True),
                ('trusted', trusted)]
        port_args = {'name': name}
        if trusted is not None:
            port_args['trusted'] = trusted
        with self.port(is_admin=True, **port_args) as port:
            for k, v in keys:
                self.assertEqual(v, port['port'][k])
            if trusted is not None:
                self.assertEqual(trusted,
                                 port['port']['binding:profile']['trusted'])
            else:
                self.assertNotIn('trusted',
                                 port['port']['binding:profile'].keys())

    def test_create_port_with_trusted_field(self):
        self._create_and_check_port_with_trusted_field(True)
        self._create_and_check_port_with_trusted_field(False)

    def test_create_port_with_trusted_field_not_set(self):
        self._create_and_check_port_with_trusted_field(None)
