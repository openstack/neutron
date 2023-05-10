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
from neutron_lib.api.definitions import port_hardware_offload_type as apidef
from neutron_lib import constants
from neutron_lib import context
from oslo_config import cfg

from neutron.db import port_hardware_offload_type_db as phot_db
from neutron.objects import ports as ports_obj
from neutron.plugins.ml2 import plugin
from neutron.tests.unit.db import test_db_base_plugin_v2


class PortHardwareOffloadTypeExtensionTestPlugin(
        plugin.Ml2Plugin,
        phot_db.PortHardwareOffloadTypeDbMixin):
    """Test plugin to mixin the port hardware offload type extension."""

    supported_extension_aliases = [apidef.ALIAS]


@ddt.ddt
class PortHardwareOffloadTypeExtensionTestCase(
         test_db_base_plugin_v2.NeutronDbPluginV2TestCase):
    """Test API extension port-hardware-offload-type attributes."""

    def setUp(self, *args):
        plugin = ('neutron.tests.unit.extensions.test_port_hardware_offload_'
                  'type.PortHardwareOffloadTypeExtensionTestPlugin')
        extension_drivers = ['port_hardware_offload_type']
        cfg.CONF.set_override('extension_drivers', extension_drivers, 'ml2')
        super().setUp(plugin=plugin)
        self.ctx = context.get_admin_context()

    def _create_and_check_port_hw_offload_type(self, hardware_offload_type):
        name = 'hw_offload_type'
        keys = [('name', name),
                ('admin_state_up', True),
                ('hardware_offload_type', hardware_offload_type)]
        port_args = {'name': name}
        if hardware_offload_type in constants.VALID_HWOL_TYPES:
            port_args['hardware_offload_type'] = hardware_offload_type
        with self.port(**port_args) as port:
            for k, v in keys:
                self.assertEqual(v, port['port'][k])

            port_ovo = ports_obj.Port.get_object(self.ctx,
                                                 id=port['port']['id'])
            self.assertEqual(1, len(port_ovo.bindings))
            # NOTE: if the HW type flag is enabled, the port binding profile
            # is set correspondingly.
            if hardware_offload_type in constants.VALID_HWOL_TYPES:
                self.assertEqual({'capabilities': [hardware_offload_type]},
                                 port_ovo.bindings[0].profile)
            else:
                self.assertEqual({}, port_ovo.bindings[0].profile)

    @ddt.data(*constants.VALID_HWOL_TYPES, None)
    def test_create_port_hardware_offload_type(self, hw_offload_type):
        self._create_and_check_port_hw_offload_type(hw_offload_type)
