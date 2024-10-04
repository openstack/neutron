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
from neutron_lib.api.definitions import uplink_status_propagation as usp
from neutron_lib.api.definitions import uplink_status_propagation_updatable \
    as apidef
from neutron_lib.db import api as db_api
from neutron_lib.db import resource_extend

from neutron.db import db_base_plugin_v2
from neutron.db import uplink_status_propagation_db as usp_db
from neutron.tests.common import test_db_base_plugin_v2


class UplinkStatusPropagationUpdatableExtensionTestPlugin(
        db_base_plugin_v2.NeutronDbPluginV2,
        usp_db.UplinkStatusPropagationMixin):
    """Test plugin to mixin the uplink status propagation extension.
    """

    supported_extension_aliases = [usp.ALIAS, apidef.ALIAS]

    # TODO(ralonsoh): update ``uplink_status_propagation_updatable`` with
    # COLLECTION_NAME=neutron_lib.api.definitions.port.COLLECTION_NAME
    @staticmethod
    @resource_extend.extends([usp.COLLECTION_NAME])
    def _extend_network_project_default(port_res, port_db):
        return usp_db.UplinkStatusPropagationMixin._extend_port_dict(
            port_res, port_db)

    def create_port(self, context, port):
        with db_api.CONTEXT_WRITER.using(context):
            new_port = super().create_port(context, port)
            # Update the propagate_uplink_status in the database
            p = port['port']
            if 'propagate_uplink_status' not in p:
                p['propagate_uplink_status'] = False
            self._process_create_port(context, p, new_port)
        return new_port

    def update_port(self, context, port_id, port, **kwargs):
        with db_api.CONTEXT_WRITER.using(context):
            new_port = super().update_port(context, port_id, port)
            # Update the propagate_uplink_status in the database
            p = port['port']
            if 'propagate_uplink_status' not in p:
                p['propagate_uplink_status'] = False
            self._process_update_port(context, p, new_port)
        return new_port


@ddt.ddt
class UplinkStatusPropagationUpdatableExtensionTestCase(
         test_db_base_plugin_v2.NeutronDbPluginV2TestCase):
    """Test API extension ``uplink-status-propagation-updatable`` attributes.
    """

    def setUp(self, **kwargs):
        plugin = ('neutron.tests.unit.extensions.test_uplink_status_'
                  'propagation_updatable.'
                  'UplinkStatusPropagationUpdatableExtensionTestPlugin')
        super().setUp(plugin=plugin)

    @ddt.data(True, False)
    def test_update_port_propagate_uplink_status(
            self, propagate_uplink_status):
        name = 'propagate_uplink_status'
        keys = [('name', name), ('admin_state_up', True),
                ('status', self.port_create_status),
                (usp.PROPAGATE_UPLINK_STATUS, propagate_uplink_status)]
        with self.port(name=name,
                       propagate_uplink_status=propagate_uplink_status
                       ) as port:
            for k, v in keys:
                self.assertEqual(v, port['port'][k])

            # Update the port with the opposite ``propagate_uplink_status``
            # value and check it.
            data = {'port': {usp.PROPAGATE_UPLINK_STATUS:
                             not propagate_uplink_status}}
            req = self.new_update_request('ports', data, port['port']['id'])
            req.get_response(self.api)
            req = self.new_show_request('ports', port['port']['id'])
            res = req.get_response(self.api)
            port = self.deserialize(self.fmt, res)['port']
            self.assertEqual(not propagate_uplink_status,
                             port[usp.PROPAGATE_UPLINK_STATUS])
