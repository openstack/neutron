# Copyright (c) 2016 Red Hat, Inc.
# All Rights Reserved.
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

import mock

import oslo_messaging
from oslo_serialization import jsonutils
from oslo_utils import uuidutils
import testtools

from neutron.api.rpc.handlers import resources_rpc
from neutron.common import utils
from neutron.objects import trunk as trunk_obj
from neutron.services.trunk import constants
from neutron.services.trunk.drivers.openvswitch.agent import exceptions
from neutron.services.trunk.drivers.openvswitch.agent import ovsdb_handler
from neutron.services.trunk.drivers.openvswitch.agent import trunk_manager
from neutron.tests import base


class TestLockOnBridgeName(base.BaseTestCase):
    def setUp(self):
        super(TestLockOnBridgeName, self).setUp()
        self.lock_mock = mock.patch('oslo_concurrency.lockutils.lock').start()
        self.method_called = False

    def test_positional_argument(self):
        @ovsdb_handler.lock_on_bridge_name(required_parameter='bridge_name')
        def testing_method(param, bridge_name, another):
            self.method_called = True

        testing_method('foo', 'bridge', 'bar')
        self.lock_mock.assert_called_once_with('bridge')
        self.assertTrue(self.method_called)

    def test_keyword_argument(self):
        @ovsdb_handler.lock_on_bridge_name(required_parameter='bridge_name')
        def testing_method(param, bridge_name, another):
            self.method_called = True

        testing_method('foo', another='baz', bridge_name='bridge')
        self.lock_mock.assert_called_once_with('bridge')
        self.assertTrue(self.method_called)

    def test_missing_argument(self):
        with testtools.ExpectedException(RuntimeError):
            @ovsdb_handler.lock_on_bridge_name(
                required_parameter='bridge_name')
            def testing_method(one, two):
                pass


class TestIsTrunkServicePort(base.BaseTestCase):
    def test_with_bridge_name(self):
        observed = ovsdb_handler.is_trunk_service_port('tbr-foo')
        self.assertTrue(observed)

    def test_with_subport_patch_port_int_side(self):
        observed = ovsdb_handler.is_trunk_service_port('spi-foo')
        self.assertTrue(observed)

    def test_with_subport_patch_port_trunk_side(self):
        observed = ovsdb_handler.is_trunk_service_port('spt-foo')
        self.assertTrue(observed)

    def test_with_trunk_patch_port_int_side(self):
        observed = ovsdb_handler.is_trunk_service_port('tpi-foo')
        self.assertTrue(observed)

    def test_with_trunk_patch_port_trunk_side(self):
        observed = ovsdb_handler.is_trunk_service_port('tpt-foo')
        self.assertTrue(observed)

    def test_with_random_string(self):
        observed = ovsdb_handler.is_trunk_service_port('foo')
        self.assertFalse(observed)


class TestBridgeHasInstancePort(base.BaseTestCase):
    def setUp(self):
        super(TestBridgeHasInstancePort, self).setUp()
        self.bridge = mock.Mock()
        self.present_interfaces = []
        self.bridge.get_iface_name_list.return_value = self.present_interfaces

    def test_only_service_ports_on_bridge(self):
        """Test when only with patch ports and bridge name are on trunk bridge.
        """
        self.present_interfaces.extend(
            ['tbr-foo', 'spt-foo', 'tpt-foo'])
        self.assertFalse(ovsdb_handler.bridge_has_instance_port(self.bridge))

    def test_device_on_bridge(self):
        """Condition is True decause of foo device is present on bridge."""
        self.present_interfaces.extend(
            ['tbr-foo', 'spt-foo', 'tpt-foo', 'foo'])
        self.assertTrue(ovsdb_handler.bridge_has_instance_port(self.bridge))

    def test_ovsdb_error(self):
        self.bridge.get_iface_name_list.side_effect = RuntimeError
        self.assertFalse(ovsdb_handler.bridge_has_instance_port(self.bridge))


class TestOVSDBHandler(base.BaseTestCase):
    """Test that RPC or OVSDB failures do not cause crash."""
    def setUp(self):
        super(TestOVSDBHandler, self).setUp()
        self.ovsdb_handler = ovsdb_handler.OVSDBHandler(mock.sentinel.manager)
        mock.patch.object(self.ovsdb_handler, 'trunk_rpc').start()
        mock.patch.object(self.ovsdb_handler, 'trunk_manager').start()
        self.trunk_manager = self.ovsdb_handler.trunk_manager
        self.trunk_id = uuidutils.generate_uuid()
        self.fake_subports = [
                trunk_obj.SubPort(
                    id=uuidutils.generate_uuid(),
                    port_id=uuidutils.generate_uuid(),
                    segmentation_id=1)]
        self.fake_port = {
            'name': 'foo',
            'external_ids': {
                'trunk_id': 'trunk_id',
                'subport_ids': jsonutils.dumps(
                    [s.id for s in self.fake_subports]),
            }
        }
        self.subport_bindings = {
            'trunk_id': [
                {'id': subport.port_id,
                 'mac_address': 'mac'} for subport in self.fake_subports]}

    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge')
    @mock.patch.object(utils, 'wait_until_true',
                       side_effect=utils.WaitTimeout)
    def test_handle_trunk_add_interface_wont_appear(self, wut, br):
        self.ovsdb_handler.handle_trunk_add('foo')
        self.assertTrue(self.trunk_manager.dispose_trunk.called)

    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge')
    def test_handle_trunk_add_rpc_failure(self, br):
        with mock.patch.object(self.ovsdb_handler, '_wire_trunk',
                side_effect=oslo_messaging.MessagingException):
            with mock.patch.object(ovsdb_handler, 'bridge_has_instance_port',
                    return_value=True):
                self.ovsdb_handler.handle_trunk_add('foo')

    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge')
    def test_handle_trunk_add_ovsdb_failure(self, br):
        with mock.patch.object(self.ovsdb_handler, '_wire_trunk',
                side_effect=RuntimeError):
            with mock.patch.object(ovsdb_handler, 'bridge_has_instance_port',
                    return_value=True):
                self.ovsdb_handler.handle_trunk_add('foo')

    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge')
    def test_handle_trunk_add_parent_port_not_found(self, br):
        with mock.patch.object(self.ovsdb_handler, '_get_parent_port',
                side_effect=exceptions.ParentPortNotFound):
            # do not wait the default timeout
            self.ovsdb_handler.timeout = 1
            self.ovsdb_handler.handle_trunk_add('foo')

    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge')
    def test_handle_trunk_add_missing_bridge(self, br):
        br.return_value.bridge_exists.return_value = False
        with mock.patch.object(
                ovsdb_handler, 'bridge_has_instance_port') as has_port_mock:
            self.ovsdb_handler.handle_trunk_add('foo')
        self.assertFalse(has_port_mock.called)

    def test_handle_trunk_remove_trunk_manager_failure(self):
        with mock.patch.object(self.ovsdb_handler, '_get_trunk_metadata',
                side_effect=trunk_manager.TrunkManagerError(error='error')):
            with mock.patch.object(ovsdb_handler, 'bridge_has_instance_port',
                    return_value=True):
                self.ovsdb_handler.handle_trunk_remove('foo', self.fake_port)

    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge')
    def test_handle_trunk_remove_rpc_failure(self, br):
        self.ovsdb_handler.trunk_rpc.update_trunk_status = (
            oslo_messaging.MessagingException)
        self.ovsdb_handler.handle_trunk_remove('foo', self.fake_port)

    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge')
    def test_wire_subports_for_trunk_trunk_manager_failure(self, br):
        with mock.patch.object(
                self.ovsdb_handler, '_update_trunk_metadata') as f:
            trunk_rpc = self.ovsdb_handler.trunk_rpc
            trunk_rpc.update_subport_bindings.return_value = (
                self.subport_bindings)
            self.trunk_manager.add_sub_port.side_effect = (
                trunk_manager.TrunkManagerError(error='error'))

            status = self.ovsdb_handler.wire_subports_for_trunk(
                None, 'trunk_id', self.fake_subports)
            self.assertTrue(f.call_count)
            self.assertEqual(constants.DEGRADED_STATUS, status)

    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge')
    def test_wire_subports_for_trunk_ovsdb_failure(self, br):
        self.ovsdb_handler.trunk_rpc.update_subport_bindings.return_value = (
            self.subport_bindings)
        with mock.patch.object(self.ovsdb_handler, '_set_trunk_metadata',
                side_effect=RuntimeError):
            status = self.ovsdb_handler.wire_subports_for_trunk(
                None, 'trunk_id', self.fake_subports)
        self.assertEqual(constants.DEGRADED_STATUS, status)

    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge')
    def test_unwire_subports_for_trunk_port_not_found(self, br):
        self.ovsdb_handler.trunk_rpc.update_subport_bindings.return_value = (
            self.subport_bindings)
        with mock.patch.object(self.ovsdb_handler, '_update_trunk_metadata',
                side_effect=exceptions.ParentPortNotFound(bridge='foo_br')):
            status = self.ovsdb_handler.unwire_subports_for_trunk(
                'trunk_id', ['subport_id'])
        self.assertEqual(constants.ACTIVE_STATUS, status)

    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge')
    def test_unwire_subports_for_trunk_trunk_manager_failure(self, br):
        with mock.patch.object(
            self.ovsdb_handler, '_update_trunk_metadata') as f:
            self.trunk_manager.remove_sub_port.side_effect = (
                trunk_manager.TrunkManagerError(error='error'))
            status = self.ovsdb_handler.unwire_subports_for_trunk(
                'foo_trunk_id', ['subport_id'])
            self.assertTrue(f.call_count)
            self.assertEqual(constants.DEGRADED_STATUS, status)

    def test__wire_trunk_get_trunk_details_failure(self):
        self.trunk_manager.get_port_uuid_from_external_ids.side_effect = (
            trunk_manager.TrunkManagerError(error='error'))
        self.ovsdb_handler._wire_trunk(mock.Mock(), self.fake_port)

    def test__wire_trunk_trunk_not_associated(self):
        self.ovsdb_handler.trunk_rpc.get_trunk_details.side_effect = (
            resources_rpc.ResourceNotFound(
                resource_id='id', resource_type='type'))
        self.ovsdb_handler._wire_trunk(mock.Mock(), self.fake_port)
        trunk_rpc = self.ovsdb_handler.trunk_rpc
        self.assertFalse(trunk_rpc.update_trunk_status.called)

    def test__wire_trunk_create_trunk_failure(self):
        self.trunk_manager.create_trunk.side_effect = (
            trunk_manager.TrunkManagerError(error='error'))
        self.ovsdb_handler._wire_trunk(mock.Mock(), self.fake_port)
        trunk_rpc = self.ovsdb_handler.trunk_rpc
        trunk_rpc.update_trunk_status.assert_called_once_with(
            mock.ANY, mock.ANY, constants.ERROR_STATUS)

    def test__wire_trunk_rewire_trunk_failure(self):
        with mock.patch.object(self.ovsdb_handler,
                               'unwire_subports_for_trunk') as f,\
                mock.patch.object(self.ovsdb_handler,
                                  'get_connected_subports_for_trunk') as g:
            g.return_value = ['stale_port']
            f.return_value = constants.DEGRADED_STATUS
            self.ovsdb_handler._wire_trunk(
                mock.Mock(), self.fake_port, rewire=True)
            trunk_rpc = self.ovsdb_handler.trunk_rpc
            trunk_rpc.update_trunk_status.assert_called_once_with(
                mock.ANY, mock.ANY, constants.DEGRADED_STATUS)

    def test__wire_trunk_report_trunk_called_on_wiring(self):
        with mock.patch.object(self.trunk_manager, 'create_trunk'),\
                mock.patch.object(self.ovsdb_handler,
                                  'wire_subports_for_trunk'):
            self.ovsdb_handler._wire_trunk(mock.Mock(), self.fake_port)
            trunk_rpc = self.ovsdb_handler.trunk_rpc
            self.assertTrue(trunk_rpc.update_trunk_status.called)

    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge')
    def test__set_trunk_metadata_with_None_params(self, br):
        mock_br = br.return_value
        with mock.patch.object(
                self.ovsdb_handler, "_get_parent_port",
                return_value={'name': 'foo', 'external_ids': {}}):
            self.ovsdb_handler._set_trunk_metadata(None, None, 'foo', [])
            mock_br.set_db_attribute.assert_called_once_with(
                'Interface', 'foo', 'external_ids',
                {'bridge_name': mock.ANY, 'trunk_id': 'foo',
                 'subport_ids': '[]'})

    def test__get_current_status_active(self):
        self.assertEqual(constants.ACTIVE_STATUS,
                         self.ovsdb_handler._get_current_status([], []))

    def test__get_current_status_degraded(self):
        self.assertEqual(constants.DEGRADED_STATUS,
                         self.ovsdb_handler._get_current_status(
                             [mock.ANY], []))

    def _test__update_trunk_metadata_wire_flag(self, mock_br, wire,
                                               external_ids,
                                               subport_ids,
                                               expected_subport_ids):
        with mock.patch.object(
                self.ovsdb_handler, "_get_parent_port",
                return_value={'name': 'foo', 'external_ids': external_ids}):
            self.ovsdb_handler._update_trunk_metadata(
                None, None, 'foo', subport_ids, wire=wire)
            external_ids = mock_br.set_db_attribute.call_args[0][3]
            self.assertEqual(1, mock_br.set_db_attribute.call_count)
            self.assertEqual(
                sorted(expected_subport_ids),
                sorted(external_ids['subport_ids']))

    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge')
    def test__update_trunk_metadata_wire(self, br):
        mock_br = br.return_value
        external_ids = {
            'subport_ids': '["foo_subport_1"]'
        }
        subport_ids = ['foo_subport_2']
        expected_subport_ids = '["foo_subport_1", "foo_subport_2"]'
        self._test__update_trunk_metadata_wire_flag(
            mock_br, True, external_ids, subport_ids, expected_subport_ids)

    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge')
    def test__update_trunk_metadata_unwire(self, br):
        mock_br = br.return_value
        external_ids = {
            'subport_ids': '["foo_subport_1", "foo_subport_2"]'
        }
        subport_ids = ['foo_subport_2']
        expected_subport_ids = '["foo_subport_1"]'
        self._test__update_trunk_metadata_wire_flag(
            mock_br, False, external_ids, subport_ids, expected_subport_ids)
