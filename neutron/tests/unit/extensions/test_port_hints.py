# Copyright 2023 Ericsson Software Technology
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import ddt
from neutron_lib.api.definitions import port_hints as phints_def
from neutron_lib.db import api as db_api

from neutron.db import db_base_plugin_v2
from neutron.db import port_hints_db as phints_db
from neutron.tests.common import test_db_base_plugin_v2

HINTS_LIST = [
    None,
    {'openvswitch': {'other_config': {'tx-steering': 'hash'}}},
]


class PortHintsExtensionTestPlugin(
        db_base_plugin_v2.NeutronDbPluginV2,
        phints_db.PortHintsMixin):
    """Test plugin to mixin the port hints extension."""

    supported_extension_aliases = [phints_def.ALIAS]

    def create_port(self, context, port):
        with db_api.CONTEXT_WRITER.using(context):
            new_port = super().create_port(context, port)
            self._process_create_port(context, port['port'], new_port)
        return new_port

    def update_port(self, context, id, port):
        with db_api.CONTEXT_WRITER.using(context):
            updated_port = super().update_port(context, id, port)
            self._process_update_port(context, port['port'], updated_port)
        return updated_port


@ddt.ddt
class PortHintsExtensionTestCase(
         test_db_base_plugin_v2.NeutronDbPluginV2TestCase):
    """Test API extension port-hints attributes."""

    def setUp(self, *args):
        plugin = ('neutron.tests.unit.extensions.test_port_hints.'
                  'PortHintsExtensionTestPlugin')
        super().setUp(plugin=plugin)

    def _create_and_check_port_hints(self, hints):
        keys = [('name', 'name_1'),
                ('admin_state_up', True),
                ('status', self.port_create_status),
                ('hints', hints)]
        with self.port(is_admin=True, name='name_1', hints=hints) as port:
            for k, v in keys:
                self.assertEqual(v, port['port'][k])
        return port

    def _update_and_check_port_hints(self, port, hints):
        data = {'port': {'hints': hints}}
        req = self.new_update_request(
            'ports', data, port['port']['id'], as_admin=True)
        res = self.deserialize(self.fmt, req.get_response(self.api))
        self.assertEqual(
            hints, res['port']['hints'])

    @ddt.data(*HINTS_LIST)
    def test_create_and_update_port_hints(
            self, hints):
        port = self._create_and_check_port_hints(hints)
        for new_hints in HINTS_LIST:
            self._update_and_check_port_hints(port, new_hints)
