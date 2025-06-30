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

from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as nlib_consts
from neutron_lib import exceptions as n_exc
from neutron_lib.services.trunk import constants as trunk_consts
from oslo_config import cfg

from neutron.common.ovn.constants import OVN_ML2_MECH_DRIVER_NAME
from neutron.objects.ports import Port
from neutron.objects.ports import PortBinding
from neutron.objects import trunk as trunk_objects
from neutron.services.trunk import drivers
from neutron.services.trunk.drivers.ovn import trunk_driver
from neutron.services.trunk import plugin as trunk_plugin
from neutron.tests import base
from neutron.tests.unit import fake_resources
from neutron.tests.unit.plugins.ml2 import test_plugin


class FakePayload:
    def __init__(self, trunk, subports=None):
        self.states = (trunk,)
        self.metadata = {'subports': subports or []}


class TestTrunkHandler(base.BaseTestCase):
    def setUp(self):
        super(TestTrunkHandler, self).setUp()
        self.context = mock.Mock()
        self.plugin_driver = mock.Mock()
        self.plugin_driver._plugin = mock.Mock()
        self.plugin_driver.nb_ovn = fake_resources.FakeOvsdbNbOvnIdl()
        self.handler = trunk_driver.OVNTrunkHandler(self.plugin_driver)
        self.trunk_1 = mock.Mock()
        self.trunk_1.port_id = "trunk-1"
        self.trunk_1_obj = self._get_fake_port_obj(
            port_id='trunk-1')

        self.trunk_2 = mock.Mock()
        self.trunk_2.port_id = "trunk-2"

        self.sub_port_1 = mock.Mock()
        self.sub_port_1.segmentation_id = 40
        self.sub_port_1.trunk_id = "trunk-1"
        self.sub_port_1.port_id = "sub_port_1"
        self.sub_port_1_obj = self._get_fake_port_obj(
            port_id='sub_port_1')

        self.sub_port_2 = mock.Mock()
        self.sub_port_2.segmentation_id = 41
        self.sub_port_2.trunk_id = "trunk-1"
        self.sub_port_2.port_id = "sub_port_2"
        self.sub_port_2_obj = self._get_fake_port_obj(
            port_id='sub_port_1')

        self.sub_port_3 = mock.Mock()
        self.sub_port_3.segmentation_id = 42
        self.sub_port_3.trunk_id = "trunk-2"
        self.sub_port_3.port_id = "sub_port_3"

        self.sub_port_4 = mock.Mock()
        self.sub_port_4.segmentation_id = 43
        self.sub_port_4.trunk_id = "trunk-2"
        self.sub_port_4.port_id = "sub_port_4"

        self.get_trunk_object = mock.patch(
            "neutron.objects.trunk.Trunk.get_object").start()
        self.get_trunk_object.side_effect = lambda ctxt, id: \
            self.trunk_1 if id == 'trunk-1' else self.trunk_2
        self.mock_get_port = mock.patch(
            "neutron.objects.ports.Port.get_object").start()
        self.mock_get_port.side_effect = lambda ctxt, id: (
            self.sub_port_1_obj if id == 'sub_port_1' else (
                self.sub_port_2_obj if id == 'sub_port_2' else
                self.trunk_1_obj if id == 'trunk-1' else None))
        self.mock_port_update = mock.patch(
            "neutron.objects.ports.Port.update").start()
        self.mock_update_pb = mock.patch(
            "neutron.objects.ports.PortBinding.update_object").start()
        self.mock_clear_levels = mock.patch(
            "neutron.objects.ports.PortBindingLevel.delete_objects").start()
        self.mock_bump_revision = mock.patch(
            "neutron.db.ovn_revision_numbers_db.bump_revision").start()

    def _get_fake_port_obj(self, port_id):
        with mock.patch('uuid.UUID') as mock_uuid:
            mock_uuid.return_value = port_id
            port = Port()
            port.id = port_id
            port.bindings = [PortBinding(profile={}, host='foo.com')]
            port.status = 'ACTIVE'
        return port

    def _assert_calls(self, mock, expected_calls):
        self.assertEqual(
            len(expected_calls),
            mock.call_count)
        mock.assert_has_calls(
            expected_calls, any_order=True)

    def test_create_trunk(self):
        self.trunk_1.sub_ports = []
        self.handler.trunk_created(
            resources.TRUNK,
            events.AFTER_CREATE,
            self.plugin_driver,
            FakePayload(self.trunk_1))
        self.plugin_driver.nb_ovn.set_lswitch_port.assert_not_called()
        self.mock_update_pb.assert_not_called()

        self.trunk_1.sub_ports = [self.sub_port_1, self.sub_port_2]
        self.handler.trunk_created(
            resources.TRUNK,
            events.AFTER_CREATE,
            self.plugin_driver,
            FakePayload(self.trunk_1))

        calls = [mock.call(), mock.call()]
        self._assert_calls(self.mock_port_update, calls)

        calls = [
            mock.call(mock.ANY,
                      {'profile': {'parent_name': trunk.port_id,
                                   'tag': s_port.segmentation_id},
                       'vif_type': portbindings.VIF_TYPE_OVS},
                      host=mock.ANY,
                      port_id=s_port.port_id)
            for trunk, s_port in [(self.trunk_1, self.sub_port_1),
                                  (self.trunk_1, self.sub_port_2)]]
        self._assert_calls(self.mock_update_pb, calls)

        calls = [mock.call(lport_name=s_port.port_id,
                           parent_name=trunk.port_id,
                           tag=s_port.segmentation_id,
                           external_ids_update={
                               'neutron:device_owner': 'trunk:subport'})
                 for trunk, s_port in [(self.trunk_1, self.sub_port_1),
                                       (self.trunk_1, self.sub_port_2)]]
        self._assert_calls(self.plugin_driver.nb_ovn.set_lswitch_port, calls)
        self.mock_clear_levels.assert_not_called()

    def test_create_trunk_port_not_found(self):
        self.trunk_1.sub_ports = [self.sub_port_4]
        self.handler.trunk_created(
            resources.TRUNK,
            events.AFTER_CREATE,
            self.plugin_driver,
            FakePayload(self.trunk_1))
        self.plugin_driver.nb_ovn.set_lswitch_port.assert_not_called()
        self.mock_update_pb.assert_not_called()

    def test_create_trunk_port_db_exception(self):
        self.trunk_1.sub_ports = [self.sub_port_1]
        self.mock_update_pb.side_effect = [n_exc.ObjectNotFound(id=1)]
        self.handler.trunk_created(
            resources.TRUNK,
            events.AFTER_CREATE,
            self.plugin_driver,
            FakePayload(self.trunk_1))
        self.mock_update_pb.assert_called_once_with(
            mock.ANY, {'profile': {'parent_name': self.sub_port_1.trunk_id,
                                   'tag': self.sub_port_1.segmentation_id},
                       'vif_type': portbindings.VIF_TYPE_OVS},
            host='foo.com', port_id=self.sub_port_1.port_id)
        self.mock_port_update.assert_not_called()
        self.plugin_driver.nb_ovn.set_lswitch_port.assert_not_called()

    def test_delete_trunk(self):
        self.trunk_1.sub_ports = []
        self.handler.trunk_deleted(
            resources.TRUNK,
            events.AFTER_DELETE,
            self.plugin_driver,
            FakePayload(self.trunk_1))
        self.plugin_driver.nb_ovn.set_lswitch_port.assert_not_called()
        self.mock_update_pb.assert_not_called()
        self.mock_clear_levels.assert_not_called()

        self.trunk_1.sub_ports = [self.sub_port_1, self.sub_port_2]
        self.sub_port_1_obj.bindings[0].profile.update({
            'tag': self.sub_port_1.segmentation_id,
            'parent_name': self.sub_port_1.trunk_id,
            'foo_field': self.sub_port_1.trunk_id})
        self.sub_port_2_obj.bindings[0].profile.update({
            'tag': self.sub_port_2.segmentation_id,
            'parent_name': self.sub_port_2.trunk_id,
            'foo_field': self.sub_port_2.trunk_id})
        self.handler.trunk_deleted(
            resources.TRUNK,
            events.AFTER_DELETE,
            self.plugin_driver,
            FakePayload(self.trunk_1))

        calls = [mock.call(), mock.call()]
        self._assert_calls(self.mock_port_update, calls)

        calls = [
            mock.call(
                mock.ANY,
                {'profile': {'foo_field': s_port.trunk_id},
                 'vif_type': portbindings.VIF_TYPE_UNBOUND},
                host='foo.com',
                port_id=s_port.port_id)
            for trunk, s_port in [(self.trunk_1, self.sub_port_1),
                                  (self.trunk_1, self.sub_port_2)]]
        self._assert_calls(self.mock_update_pb, calls)

        calls = [
            mock.call(mock.ANY,
                      host='foo.com',
                      port_id=s_port.port_id)
            for trunk, s_port in [(self.trunk_1, self.sub_port_1),
                                  (self.trunk_1, self.sub_port_2)]]
        self._assert_calls(self.mock_clear_levels, calls)

        calls = [mock.call(lport_name=s_port.port_id,
                           parent_name=[],
                           tag=[],
                           up=False,
                           external_ids_update={'neutron:device_owner': ''})
                 for trunk, s_port in [(self.trunk_1, self.sub_port_1),
                                       (self.trunk_1, self.sub_port_2)]]
        self._assert_calls(self.plugin_driver.nb_ovn.set_lswitch_port, calls)

    def test_delete_trunk_key_not_found(self):
        self.sub_port_1_obj.bindings[0].profile.update({
            'foo_field': self.sub_port_1.trunk_id})
        self.trunk_1.sub_ports = [self.sub_port_1]
        self.handler.trunk_deleted(
            resources.TRUNK,
            events.AFTER_DELETE,
            self.plugin_driver,
            FakePayload(self.trunk_1))
        calls = [
            mock.call(mock.ANY,
                      {'profile': {'foo_field': s_port.trunk_id},
                       'vif_type': portbindings.VIF_TYPE_UNBOUND},
                      host='foo.com',
                      port_id=s_port.port_id)
            for trunk, s_port in [(self.trunk_1, self.sub_port_1)]]
        self._assert_calls(self.mock_update_pb, calls)

        calls = [
            mock.call(mock.ANY,
                      host='foo.com',
                      port_id=s_port.port_id)
            for trunk, s_port in [(self.trunk_1, self.sub_port_1)]]
        self._assert_calls(self.mock_clear_levels, calls)

        calls = [mock.call(lport_name=s_port.port_id,
                           parent_name=[],
                           tag=[],
                           up=False,
                           external_ids_update={'neutron:device_owner': ''})
                 for trunk, s_port in [(self.trunk_1, self.sub_port_1)]]
        self._assert_calls(self.plugin_driver.nb_ovn.set_lswitch_port, calls)

    def test_delete_trunk_port_not_found(self):
        self.trunk_1.sub_ports = [self.sub_port_4]
        self.handler.trunk_deleted(
            resources.TRUNK,
            events.AFTER_DELETE,
            self.plugin_driver,
            FakePayload(self.trunk_1))
        self.plugin_driver.nb_ovn.set_lswitch_port.assert_not_called()
        self.mock_update_pb.assert_not_called()
        self.mock_clear_levels.assert_not_called()

    def test_delete_trunk_port_db_exception(self):
        self.trunk_1.sub_ports = [self.sub_port_1]
        self.mock_update_pb.side_effect = [n_exc.ObjectNotFound(id=1)]
        self.handler.trunk_deleted(
            resources.TRUNK,
            events.AFTER_DELETE,
            self.plugin_driver,
            FakePayload(self.trunk_1))
        self.mock_update_pb.assert_called_once_with(
            mock.ANY, {'profile': {},
                       'vif_type': portbindings.VIF_TYPE_UNBOUND},
            host='foo.com', port_id=self.sub_port_1.port_id)
        self.mock_port_update.assert_not_called()
        self.plugin_driver.nb_ovn.set_lswitch_port.assert_not_called()
        self.mock_clear_levels.assert_not_called()

    @staticmethod
    def _fake_trunk_event_payload():
        original_trunk = mock.Mock()
        original_trunk.port_id = 'original_trunk_port_id'
        current_trunk = mock.Mock()
        current_trunk.port_id = 'current_trunk_port_id'

        payload = mock.Mock()
        payload.states = (original_trunk, current_trunk)

        current_subport = mock.Mock()
        current_subport.segmentation_id = 40
        current_subport.trunk_id = 'current_trunk_port_id'
        current_subport.port_id = 'current_subport_port_id'
        original_subport = mock.Mock()
        original_subport.segmentation_id = 41
        original_subport.trunk_id = 'original_trunk_port_id'
        original_subport.port_id = 'original_subport_port_id'
        current_trunk.sub_ports = [current_subport]
        original_trunk.sub_ports = [original_subport]

        return payload

    @mock.patch.object(trunk_driver.OVNTrunkHandler, '_set_sub_ports')
    def test_trunk_created(self, set_subports):
        fake_payload = self._fake_trunk_event_payload()
        self.handler.trunk_created(
            resources.TRUNK,
            events.AFTER_CREATE,
            self.plugin_driver,
            fake_payload)
        set_subports.assert_called_once_with(
            fake_payload.states[0].port_id,
            fake_payload.states[0].sub_ports)
        fake_payload.states[0].update.assert_called_once_with(
            status=trunk_consts.TRUNK_ACTIVE_STATUS)

    @mock.patch.object(trunk_driver.OVNTrunkHandler, '_unset_sub_ports')
    def test_trunk_deleted(self, unset_subports):
        fake_payload = self._fake_trunk_event_payload()
        self.handler.trunk_deleted(
            resources.TRUNK,
            events.AFTER_DELETE,
            self.plugin_driver,
            fake_payload)
        unset_subports.assert_called_once_with(
            fake_payload.states[0].sub_ports)

    @staticmethod
    def _fake_subport_event_payload():
        original_trunk = mock.Mock()
        original_trunk.port_id = 'original_trunk_port_id'

        payload = mock.Mock()
        payload.states = (original_trunk,)

        original_subport = mock.Mock()
        original_subport.segmentation_id = 41
        original_subport.trunk_id = 'original_trunk_port_id'
        original_subport.port_id = 'original_subport_port_id'
        payload.metadata = {'subports': [original_subport]}

        return payload

    def test_subports_added(self):
        with mock.patch.object(self.handler, '_set_sub_ports') as set_s:
            self.handler.subports_added(
                resources.SUBPORTS,
                events.AFTER_CREATE,
                self.plugin_driver,
                FakePayload(self.trunk_1,
                            [self.sub_port_1, self.sub_port_2]))
        set_s.assert_called_once_with(
            self.trunk_1.port_id, [self.sub_port_1, self.sub_port_2])
        self.trunk_1.update.assert_called_once_with(
            status=trunk_consts.TRUNK_ACTIVE_STATUS)

    @mock.patch.object(trunk_driver.OVNTrunkHandler, '_set_sub_ports')
    def test_subports_added_no_subports(self, m__set_sub_ports):
        fake_payload = self._fake_subport_event_payload()
        fake_payload.metadata['subports'] = []
        self.handler.subports_added(
            resources.SUBPORTS,
            events.AFTER_CREATE,
            self.plugin_driver,
            fake_payload)
        m__set_sub_ports.assert_not_called()

    @mock.patch.object(trunk_driver.OVNTrunkHandler, '_set_sub_ports')
    def test_subports_added_no_parent(self, m__set_sub_ports):
        fake_payload = self._fake_subport_event_payload()
        self.plugin_driver.nb_ovn.lookup.return_value = None
        self.handler.subports_added(
            resources.SUBPORTS,
            events.AFTER_CREATE,
            self.plugin_driver,
            fake_payload)
        m__set_sub_ports.assert_not_called()

    def test_subports_deleted(self):
        with mock.patch.object(self.handler, '_unset_sub_ports') as unset_s:
            self.handler.subports_deleted(
                resources.SUBPORTS,
                events.AFTER_DELETE,
                self.plugin_driver,
                FakePayload(self.trunk_1,
                            [self.sub_port_1, self.sub_port_2]))
        unset_s.assert_called_once_with(
            [self.sub_port_1, self.sub_port_2])
        self.trunk_1.update.assert_called_once_with(
            status=trunk_consts.TRUNK_ACTIVE_STATUS)

    @mock.patch.object(trunk_driver.OVNTrunkHandler, '_unset_sub_ports')
    def test_subports_deleted_no_subports(self, m__unset_sub_ports):
        fake_payload = self._fake_subport_event_payload()
        fake_payload.metadata['subports'] = []
        self.handler.subports_deleted(
            resources.SUBPORTS,
            events.AFTER_DELETE,
            self.plugin_driver,
            fake_payload)
        m__unset_sub_ports.assert_not_called()

    @mock.patch.object(trunk_driver.OVNTrunkHandler, '_unset_sub_ports')
    def test_subports_deleted_no_parent(self, m__unset_sub_ports):
        fake_payload = self._fake_subport_event_payload()
        self.plugin_driver.nb_ovn.lookup.return_value = None
        self.handler.subports_deleted(
            resources.SUBPORTS,
            events.AFTER_DELETE,
            self.plugin_driver,
            fake_payload)
        m__unset_sub_ports.assert_not_called()


class TestTrunkHandlerWithPlugin(test_plugin.Ml2PluginV2TestCase):
    def setUp(self):
        super().setUp()
        self.drivers_patch = mock.patch.object(drivers, 'register').start()
        self.compat_patch = mock.patch.object(
            trunk_plugin.TrunkPlugin, 'check_compatibility').start()
        self.trunk_plugin = trunk_plugin.TrunkPlugin()
        self.trunk_plugin.add_segmentation_type('vlan', lambda x: True)
        self.plugin_driver = mock.Mock()
        self.trunk_handler = trunk_driver.OVNTrunkHandler(self.plugin_driver)

    def _create_test_trunk(self, port, subports=None):
        subports = subports if subports else []
        trunk = {'port_id': port['port']['id'],
                 'project_id': 'test_tenant',
                 'sub_ports': subports}
        response = (
            self.trunk_plugin.create_trunk(self.context, {'trunk': trunk}))
        return response

    def _get_trunk_obj(self, trunk_id):
        return trunk_objects.Trunk.get_object(self.context, id=trunk_id)

    def test_parent_active_triggers_trunk_active(self):
        with self.port() as new_parent:
            new_parent['status'] = nlib_consts.PORT_STATUS_ACTIVE
            old_parent = {'status': nlib_consts.PORT_STATUS_DOWN}
            old_trunk = self._create_test_trunk(new_parent)
            old_trunk = self._get_trunk_obj(old_trunk['id'])
            old_trunk.update(status=trunk_consts.TRUNK_DOWN_STATUS)
            trunk_details = {'trunk_id': old_trunk.id}
            new_parent['trunk_details'] = trunk_details
            old_parent['trunk_details'] = trunk_details
            self.trunk_handler.port_updated(
                resources.PORT,
                events.AFTER_UPDATE,
                None,
                payload=events.DBEventPayload(
                    self.context, states=(old_parent, new_parent)))
            new_trunk = self._get_trunk_obj(old_trunk.id)
            self.assertEqual(
                trunk_consts.TRUNK_ACTIVE_STATUS, new_trunk.status)

    def test_parent_build_does_not_trigger_trunk_active(self):
        with self.port() as new_parent:
            new_parent['status'] = nlib_consts.PORT_STATUS_BUILD
            old_parent = {'status': nlib_consts.PORT_STATUS_DOWN}
            old_trunk = self._create_test_trunk(new_parent)
            old_trunk = self._get_trunk_obj(old_trunk['id'])
            old_trunk.update(status=trunk_consts.TRUNK_DOWN_STATUS)
            trunk_details = {'trunk_id': old_trunk.id}
            new_parent['trunk_details'] = trunk_details
            old_parent['trunk_details'] = trunk_details
            self.trunk_handler.port_updated(
                resources.PORT,
                events.AFTER_UPDATE,
                None,
                payload=events.DBEventPayload(
                    self.context, states=(old_parent, new_parent)))
            new_trunk = self._get_trunk_obj(old_trunk.id)
            self.assertNotEqual(
                trunk_consts.TRUNK_ACTIVE_STATUS, new_trunk.status)


class TestTrunkDriver(base.BaseTestCase):
    def setUp(self):
        super(TestTrunkDriver, self).setUp()

    def test_is_loaded(self):
        driver = trunk_driver.OVNTrunkDriver.create(mock.Mock())
        cfg.CONF.set_override('mechanism_drivers',
                              ["logger", OVN_ML2_MECH_DRIVER_NAME],
                              group='ml2')
        self.assertTrue(driver.is_loaded)

        cfg.CONF.set_override('mechanism_drivers',
                              ['ovs', 'logger'],
                              group='ml2')
        self.assertFalse(driver.is_loaded)

        cfg.CONF.set_override('core_plugin', 'some_plugin')
        self.assertFalse(driver.is_loaded)

    def test_register(self):
        driver = trunk_driver.OVNTrunkDriver.create(mock.Mock())
        with mock.patch.object(registry, 'subscribe') as mock_subscribe:
            driver.register(mock.ANY, mock.ANY, mock.Mock())
            calls = [
                mock.call.mock_subscribe(
                    mock.ANY, resources.TRUNK, events.AFTER_CREATE),
                mock.call.mock_subscribe(
                    mock.ANY, resources.TRUNK, events.AFTER_DELETE),
                mock.call.mock_subscribe(
                    mock.ANY, resources.SUBPORTS, events.AFTER_CREATE),
                mock.call.mock_subscribe(
                    mock.ANY, resources.SUBPORTS, events.AFTER_DELETE),
            ]
            mock_subscribe.assert_has_calls(calls, any_order=True)
