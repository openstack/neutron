# Copyright (c) 2020 Red Hat, Inc.
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
from neutron_lib.api.definitions import port_device_profile as apidef
from neutron_lib.db import api as db_api

from neutron.db import db_base_plugin_v2
from neutron.db import port_device_profile_db as pdp_db
from neutron.tests.unit.db import test_db_base_plugin_v2


class PortDeviceProfileExtensionTestPlugin(
        db_base_plugin_v2.NeutronDbPluginV2,
        pdp_db.PortDeviceProfileMixin):
    """Test plugin to mixin the port device profile extension."""

    supported_extension_aliases = [apidef.ALIAS]

    def create_port(self, context, port):
        with db_api.CONTEXT_WRITER.using(context):
            new_port = super(PortDeviceProfileExtensionTestPlugin,
                             self).create_port(context, port)
            self._process_create_port(context, port['port'], new_port)
        return new_port


@ddt.ddt
class PortDeviceProfileExtensionTestCase(
         test_db_base_plugin_v2.NeutronDbPluginV2TestCase):
    """Test API extension numa_affinity_policy attributes."""

    def setUp(self, *args):
        plugin = ('neutron.tests.unit.extensions.test_port_device_profile.'
                  'PortDeviceProfileExtensionTestPlugin')
        super(PortDeviceProfileExtensionTestCase, self).setUp(plugin=plugin)

    @ddt.data('device_profile_1', None)
    def test_create_and_check_port_device_profile(self, device_profile):
        keys = [('name', 'name_1'),
                ('admin_state_up', True),
                ('status', self.port_create_status),
                ('device_profile', device_profile)]
        with self.port(name='name_1', device_profile=device_profile) as port:
            for k, v in keys:
                self.assertEqual(v, port['port'][k])
        return port
