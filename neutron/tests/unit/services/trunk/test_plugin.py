# Copyright 2016 Hewlett Packard Enterprise Development Company, LP
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

import mock

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron import manager
from neutron.objects import trunk as trunk_objects
from neutron.services.trunk import constants
from neutron.services.trunk import exceptions as trunk_exc
from neutron.services.trunk import plugin as trunk_plugin
from neutron.tests.unit.plugins.ml2 import test_plugin


def create_subport_dict(port_id):
    return {'segmentation_type': 'vlan',
            'segmentation_id': 123,
            'port_id': port_id}


def register_mock_callback(resource, event):
    callback = mock.Mock()
    registry.subscribe(callback, resource, event)
    return callback


class TrunkPluginTestCase(test_plugin.Ml2PluginV2TestCase):

    def setUp(self):
        super(TrunkPluginTestCase, self).setUp()
        self.trunk_plugin = trunk_plugin.TrunkPlugin()
        self.trunk_plugin.add_segmentation_type('vlan', lambda x: True)

    def _create_test_trunk(self, port, subports=None):
        subports = subports if subports else []
        trunk = {'port_id': port['port']['id'],
                 'tenant_id': 'test_tenant',
                 'sub_ports': subports}
        response = (
            self.trunk_plugin.create_trunk(self.context, {'trunk': trunk}))
        return response

    def _get_subport_obj(self, port_id):
        subports = trunk_objects.SubPort.get_objects(
            self.context, port_id=port_id)
        return subports[0]

    def test_delete_trunk_raise_in_use(self):
        with self.port() as port:
            trunk = self._create_test_trunk(port)
            core_plugin = manager.NeutronManager.get_plugin()
            port['port']['binding:host_id'] = 'host'
            core_plugin.update_port(self.context, port['port']['id'], port)
            self.assertRaises(trunk_exc.TrunkInUse,
                              self.trunk_plugin.delete_trunk,
                              self.context, trunk['id'])

    def _test_subports_action_notify(self, event, payload_key):
        with self.port() as parent_port, self.port() as child_port:
            trunk = self._create_test_trunk(parent_port)
            subport = create_subport_dict(child_port['port']['id'])
            callback = register_mock_callback(constants.SUBPORTS, event)
            self.trunk_plugin.add_subports(
                self.context, trunk['id'], [subport])
            subport_obj = self._get_subport_obj(subport['port_id'])
            self.trunk_plugin.remove_subports(
                self.context, trunk['id'], [subport])
            payload = {payload_key: [subport_obj]}
            callback.assert_called_once_with(
                constants.SUBPORTS, event, self.trunk_plugin, **payload)

    def test_add_subports_notify(self):
        self._test_subports_action_notify(events.AFTER_CREATE,
                                          'added_subports')

    def test_remove_subports_notify(self):
        self._test_subports_action_notify(events.AFTER_DELETE,
                                          'removed_subports')
