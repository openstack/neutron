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
from neutron_lib.api.definitions import uplink_status_propagation as apidef
from neutron_lib.db import api as db_api
from neutron_lib.db import resource_extend

from neutron.db import db_base_plugin_v2
from neutron.db import uplink_status_propagation_db as usp_db
from neutron.tests.unit.db import test_db_base_plugin_v2


class UplinkStatusPropagationExtensionTestPlugin(
        db_base_plugin_v2.NeutronDbPluginV2,
        usp_db.UplinkStatusPropagationMixin):
    """Test plugin to mixin the uplink status propagation extension.
    """

    supported_extension_aliases = [apidef.ALIAS]

    @staticmethod
    @resource_extend.extends([apidef.COLLECTION_NAME])
    def _extend_network_project_default(port_res, port_db):
        return usp_db.UplinkStatusPropagationMixin._extend_port_dict(
            port_res, port_db)

    def create_port(self, context, port):
        with db_api.CONTEXT_WRITER.using(context):
            new_port = super(UplinkStatusPropagationExtensionTestPlugin,
                            self).create_port(context, port)
            # Update the propagate_uplink_status in the database
            p = port['port']
            if 'propagate_uplink_status' not in p:
                p['propagate_uplink_status'] = False
            self._process_create_port(context, p, new_port)
        return new_port


@ddt.ddt
class UplinkStatusPropagationExtensionTestCase(
         test_db_base_plugin_v2.NeutronDbPluginV2TestCase):
    """Test API extension propagate_uplink_status attributes.
    """

    def setUp(self):
        plugin = ('neutron.tests.unit.extensions.test_uplink_status_'
                  'propagation.UplinkStatusPropagationExtensionTestPlugin')
        super(UplinkStatusPropagationExtensionTestCase,
              self).setUp(plugin=plugin)

    @ddt.data(True, False)
    def test_create_port_propagate_uplink_status(
            self, propagate_uplink_status):
        name = 'propagate_uplink_status'
        keys = [('name', name), ('admin_state_up', True),
                ('status', self.port_create_status),
                ('propagate_uplink_status', propagate_uplink_status)]
        with self.port(name=name,
                       propagate_uplink_status=propagate_uplink_status
                       ) as port:
            for k, v in keys:
                self.assertEqual(v, port['port'][k])
