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

import testtools

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron import manager
from neutron.objects import trunk as trunk_objects
from neutron.services.trunk import callbacks
from neutron.services.trunk import constants
from neutron.services.trunk import drivers
from neutron.services.trunk import exceptions as trunk_exc
from neutron.services.trunk import plugin as trunk_plugin
from neutron.tests.unit.plugins.ml2 import test_plugin
from neutron.tests.unit.services.trunk import fakes


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
        self.drivers_patch = mock.patch.object(drivers, 'register').start()
        self.compat_patch = mock.patch.object(
            trunk_plugin.TrunkPlugin, 'check_compatibility').start()
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

    def _get_trunk_obj(self, trunk_id):
        return trunk_objects.Trunk.get_object(self.context, id=trunk_id)

    def _get_subport_obj(self, port_id):
        subports = trunk_objects.SubPort.get_objects(
            self.context, port_id=port_id)
        return subports[0]

    def _test_delete_port_raise_in_use(self, parent_port, child_port, port_id,
                                       exception):
        subport = create_subport_dict(child_port['port']['id'])
        self._create_test_trunk(parent_port, [subport])
        core_plugin = manager.NeutronManager.get_plugin()
        self.assertRaises(exception, core_plugin.delete_port,
                          self.context, port_id)

    def test_delete_port_raise_in_use_by_trunk(self):
        with self.port() as parent_port, self.port() as child_port:
            self._test_delete_port_raise_in_use(
                parent_port, child_port, parent_port['port']['id'],
                trunk_exc.PortInUseAsTrunkParent)

    def test_delete_port_raise_in_use_by_subport(self):
        with self.port() as parent_port, self.port() as child_port:
            self._test_delete_port_raise_in_use(
                parent_port, child_port, child_port['port']['id'],
                trunk_exc.PortInUseAsSubPort)

    def test_delete_trunk_raise_in_use(self):
        with self.port() as port:
            trunk = self._create_test_trunk(port)
            core_plugin = manager.NeutronManager.get_plugin()
            port['port']['binding:host_id'] = 'host'
            core_plugin.update_port(self.context, port['port']['id'], port)
            self.assertRaises(trunk_exc.TrunkInUse,
                              self.trunk_plugin.delete_trunk,
                              self.context, trunk['id'])

    def _test_trunk_create_notify(self, event):
        with self.port() as parent_port:
            callback = register_mock_callback(constants.TRUNK, event)
            trunk = self._create_test_trunk(parent_port)
            trunk_obj = self._get_trunk_obj(trunk['id'])
            payload = callbacks.TrunkPayload(self.context, trunk['id'],
                                             current_trunk=trunk_obj)
            callback.assert_called_once_with(
                constants.TRUNK, event, self.trunk_plugin, payload=payload)

    def test_create_trunk_notify_after_create(self):
        self._test_trunk_create_notify(events.AFTER_CREATE)

    def test_create_trunk_notify_precommit_create(self):
        self._test_trunk_create_notify(events.PRECOMMIT_CREATE)

    def _test_trunk_update_notify(self, event):
        with self.port() as parent_port:
            callback = register_mock_callback(constants.TRUNK, event)
            trunk = self._create_test_trunk(parent_port)
            orig_trunk_obj = self._get_trunk_obj(trunk['id'])
            trunk_req = {'trunk': {'name': 'foo'}}
            self.trunk_plugin.update_trunk(self.context, trunk['id'],
                                           trunk_req)
            trunk_obj = self._get_trunk_obj(trunk['id'])
            payload = callbacks.TrunkPayload(self.context, trunk['id'],
                                             original_trunk=orig_trunk_obj,
                                             current_trunk=trunk_obj)
            callback.assert_called_once_with(
                constants.TRUNK, event, self.trunk_plugin, payload=payload)

    def test_trunk_update_notify_after_update(self):
        self._test_trunk_update_notify(events.AFTER_UPDATE)

    def test_trunk_update_notify_precommit_update(self):
        self._test_trunk_update_notify(events.PRECOMMIT_UPDATE)

    def _test_trunk_delete_notify(self, event):
        with self.port() as parent_port:
            callback = register_mock_callback(constants.TRUNK, event)
            trunk = self._create_test_trunk(parent_port)
            trunk_obj = self._get_trunk_obj(trunk['id'])
            self.trunk_plugin.delete_trunk(self.context, trunk['id'])
            payload = callbacks.TrunkPayload(self.context, trunk['id'],
                                             original_trunk=trunk_obj)
            callback.assert_called_once_with(
                constants.TRUNK, event, self.trunk_plugin, payload=payload)

    def test_delete_trunk_notify_after_delete(self):
        self._test_trunk_delete_notify(events.AFTER_DELETE)

    def test_delete_trunk_notify_precommit_delete(self):
        self._test_trunk_delete_notify(events.PRECOMMIT_DELETE)

    def _test_subport_action_empty_list_no_notify(self, event, subport_method):
        with self.port() as parent_port:
            trunk = self._create_test_trunk(parent_port)
            callback = register_mock_callback(constants.SUBPORTS, event)
            subport_method(self.context, trunk['id'], {'sub_ports': []})
            callback.assert_not_called()

    def _test_add_subports_no_notification(self, event):
        self._test_subport_action_empty_list_no_notify(
            event, self.trunk_plugin.add_subports)

    def test_add_subports_notify_after_create_empty_list(self):
        self._test_add_subports_no_notification(events.AFTER_CREATE)

    def test_add_subports_notify_precommit_create_empty_list(self):
        self._test_add_subports_no_notification(events.PRECOMMIT_CREATE)

    def _test_remove_subports_no_notification(self, event):
        self._test_subport_action_empty_list_no_notify(
            event, self.trunk_plugin.remove_subports)

    def test_remove_subports_notify_after_delete_empty_list(self):
        self._test_remove_subports_no_notification(events.AFTER_DELETE)

    def test_remove_subports_notify_precommit_delete_empty_list(self):
        self._test_remove_subports_no_notification(events.PRECOMMIT_DELETE)

    def _test_add_subports_notify(self, event):
        with self.port() as parent_port, self.port() as child_port:
            trunk = self._create_test_trunk(parent_port)
            orig_trunk_obj = self._get_trunk_obj(trunk['id'])
            subport = create_subport_dict(child_port['port']['id'])
            callback = register_mock_callback(constants.SUBPORTS, event)
            self.trunk_plugin.add_subports(
                self.context, trunk['id'], {'sub_ports': [subport]})
            trunk_obj = self._get_trunk_obj(trunk['id'])
            subport_obj = self._get_subport_obj(subport['port_id'])
            payload = callbacks.TrunkPayload(self.context, trunk['id'],
                                             current_trunk=trunk_obj,
                                             original_trunk=orig_trunk_obj,
                                             subports=[subport_obj])
            callback.assert_called_once_with(
                constants.SUBPORTS, event, self.trunk_plugin, payload=payload)

    def test_add_subports_notify_after_create(self):
        self._test_add_subports_notify(events.AFTER_CREATE)

    def test_add_subports_notify_precommit_create(self):
        self._test_add_subports_notify(events.PRECOMMIT_CREATE)

    def _test_remove_subports_notify(self, event):
        with self.port() as parent_port, self.port() as child_port:
            subport = create_subport_dict(child_port['port']['id'])
            trunk = self._create_test_trunk(parent_port, [subport])
            orig_trunk_obj = self._get_trunk_obj(trunk['id'])
            callback = register_mock_callback(constants.SUBPORTS, event)
            subport_obj = self._get_subport_obj(subport['port_id'])
            self.trunk_plugin.remove_subports(
                self.context, trunk['id'], {'sub_ports': [subport]})
            trunk_obj = self._get_trunk_obj(trunk['id'])
            payload = callbacks.TrunkPayload(self.context, trunk['id'],
                                             current_trunk=trunk_obj,
                                             original_trunk=orig_trunk_obj,
                                             subports=[subport_obj])
            callback.assert_called_once_with(
                constants.SUBPORTS, event, self.trunk_plugin, payload=payload)

    def test_remove_subports_notify_after_delete(self):
        self._test_remove_subports_notify(events.AFTER_DELETE)

    def test_remove_subports_notify_precommit_delete(self):
        self._test_remove_subports_notify(events.PRECOMMIT_DELETE)

    def test_create_trunk_in_down_state(self):
        with self.port() as port:
            trunk = self._create_test_trunk(port)
            self.assertEqual(
                constants.DOWN_STATUS, trunk['status'])

    def test_add_subports_trunk_in_error_state_raises(self):
        with self.port() as port, self.port() as subport:
            trunk = self._create_test_trunk(port)
            trunk_obj = self._get_trunk_obj(trunk['id'])
            trunk_obj.status = constants.ERROR_STATUS
            trunk_obj.update()
            s = create_subport_dict(subport['port']['id'])
            self.assertRaises(trunk_exc.TrunkInErrorState,
                self.trunk_plugin.add_subports,
                self.context, trunk['id'], {'sub_ports': [s]})

    def test_add_subports_trunk_goes_to_down(self):
        with self.port() as port, self.port() as subport:
            trunk = self._create_test_trunk(port)
            trunk_obj = self._get_trunk_obj(trunk['id'])
            trunk_obj.status = constants.ACTIVE_STATUS
            trunk_obj.update()
            s = create_subport_dict(subport['port']['id'])
            trunk = self.trunk_plugin.add_subports(
                self.context, trunk['id'], {'sub_ports': [s]})
            self.assertEqual(constants.DOWN_STATUS, trunk['status'])

    def test_remove_subports_trunk_goes_to_down(self):
        with self.port() as port, self.port() as subport:
            s = create_subport_dict(subport['port']['id'])
            trunk = self._create_test_trunk(port, [s])
            trunk_obj = self._get_trunk_obj(trunk['id'])
            trunk_obj.status = constants.ACTIVE_STATUS
            trunk_obj.update()
            trunk = self.trunk_plugin.remove_subports(
                self.context, trunk['id'],
                {'sub_ports': [{'port_id': subport['port']['id']}]})
            self.assertEqual(constants.DOWN_STATUS, trunk['status'])


class TrunkPluginDriversTestCase(test_plugin.Ml2PluginV2TestCase):

    def setUp(self):
        super(TrunkPluginDriversTestCase, self).setUp()
        mock.patch.object(drivers, 'register').start()

    def test_plugin_fails_to_start(self):
        with testtools.ExpectedException(
                trunk_exc.IncompatibleTrunkPluginConfiguration):
            trunk_plugin.TrunkPlugin()

    def test_plugin_with_fake_driver(self):
        fake_driver = fakes.FakeDriver.create()
        plugin = trunk_plugin.TrunkPlugin()
        self.assertTrue(fake_driver.is_loaded)
        self.assertEqual(set([]), plugin.supported_agent_types)
        self.assertEqual(set(['foo_intfs']), plugin.supported_interfaces)
        self.assertEqual([fake_driver], plugin.registered_drivers)
