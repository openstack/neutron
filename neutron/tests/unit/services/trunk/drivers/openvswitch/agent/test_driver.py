# Copyright 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from unittest import mock

import oslo_messaging
from oslo_utils import uuidutils

from neutron.api.rpc.callbacks import events
from neutron.api.rpc.callbacks import resources
from neutron.objects import trunk as trunk_obj
from neutron.services.trunk.drivers.openvswitch.agent import driver
from neutron.services.trunk.drivers.openvswitch.agent import ovsdb_handler
from neutron.tests import base

TRUNK_MANAGER = ('neutron.services.trunk.drivers.openvswitch.agent.'
                 'trunk_manager.TrunkManager')


class OvsTrunkSkeletonTest(base.BaseTestCase):

    def setUp(self):
        super(OvsTrunkSkeletonTest, self).setUp()
        trunk_manager_cls_mock = mock.patch(TRUNK_MANAGER).start()
        self.trunk_manager = trunk_manager_cls_mock.return_value
        handler = ovsdb_handler.OVSDBHandler(self.trunk_manager)
        mock.patch.object(handler, 'trunk_rpc').start()
        mock.patch.object(handler, '_set_trunk_metadata').start()
        mock.patch.object(
            handler, 'manages_this_trunk', return_value=True).start()

        self.skeleton = driver.OVSTrunkSkeleton(handler)
        self.trunk_id = uuidutils.generate_uuid()
        self.subports = [
            trunk_obj.SubPort(
                port_id=uuidutils.generate_uuid(),
                trunk_id=self.trunk_id,
                segmentation_type='foo',
                segmentation_id=i)
            for i in range(2)]

    @mock.patch("neutron.api.rpc.callbacks.resource_manager."
                "ConsumerResourceCallbacksManager.unregister")
    def test___init__(self, mocked_unregister):
        test_obj = driver.OVSTrunkSkeleton(mock.ANY)
        mocked_unregister.assert_called_with(test_obj.handle_trunks,
                                             resources.TRUNK)

    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge')
    def test_handle_subports_created(self, br):
        """Test handler calls into trunk manager for adding subports."""
        def fake_update_subport_bindings(context, subports):
            return {
                self.trunk_id: [
                    {'id': subport.port_id,
                     'mac_address': "mac%d" % subport.segmentation_id}
                    for subport in subports]}
        trunk_rpc = self.skeleton.ovsdb_handler.trunk_rpc
        trunk_rpc.update_subport_bindings.side_effect = (
                fake_update_subport_bindings)

        self.skeleton.handle_subports(mock.Mock(), 'SUBPORTS',
                                      self.subports, events.CREATED)
        expected_calls = [
            mock.call(subport.trunk_id, subport.port_id, mock.ANY,
                      subport.segmentation_id)
            for subport in self.subports]
        self.trunk_manager.add_sub_port.assert_has_calls(expected_calls)

    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge')
    def test_handle_subports_deleted(self, br):
        """Test handler calls into trunk manager for deleting subports."""
        self.skeleton.handle_subports(mock.Mock(), 'SUBPORTS',
                                      self.subports, events.DELETED)
        expected_calls = [
            mock.call(subport.trunk_id, subport.port_id)
            for subport in self.subports]
        self.trunk_manager.remove_sub_port.assert_has_calls(expected_calls)

    def test_handle_subports_not_for_this_agent(self):
        with mock.patch.object(self.skeleton, 'ovsdb_handler') as handler_m:
            handler_m.manages_this_trunk.return_value = False
            self.skeleton.handle_subports(mock.Mock(), 'SUBPORTS',
                                          self.subports, mock.ANY)
        self.assertFalse(self.trunk_manager.wire_subports_for_trunk.called)
        self.assertFalse(self.trunk_manager.unwire_subports_for_trunk.called)

    def test_handle_subports_unknown_event(self):
        trunk_rpc = self.skeleton.ovsdb_handler.trunk_rpc
        # unknown events should be ignored and thus lead to no updates
        # and no trunk interactions.
        with mock.patch.object(
            self.skeleton.ovsdb_handler,
            'wire_subports_for_trunk') as f,\
                mock.patch.object(
                    self.skeleton.ovsdb_handler,
                    'unwire_subports_for_trunk') as g:
            self.skeleton.handle_subports(mock.Mock(), 'SUBPORTS',
                                          self.subports, events.UPDATED)
            self.assertFalse(f.called)
            self.assertFalse(g.called)
            self.assertFalse(trunk_rpc.update_trunk_status.called)

    def test_handle_subports_trunk_rpc_error(self):
        trunk_rpc = self.skeleton.ovsdb_handler.trunk_rpc
        trunk_rpc.update_subport_bindings.side_effect = (
            oslo_messaging.MessagingException)
        self.skeleton.handle_subports(mock.Mock(), 'SUBPORTS',
                                      self.subports, events.CREATED)
        self.assertTrue(trunk_rpc.update_subport_bindings.called)

    def _test_handle_subports_trunk_on_trunk_update(self, event):
        trunk_rpc = self.skeleton.ovsdb_handler.trunk_rpc
        self.skeleton.handle_subports(mock.Mock(), 'SUBPORTS',
                                      self.subports, event)
        # Make sure trunk state is reported to the server
        self.assertTrue(trunk_rpc.update_trunk_status.called)

    def test_handle_subports_created_trunk_on_trunk_update(self):
        with mock.patch.object(
                self.skeleton.ovsdb_handler, 'wire_subports_for_trunk'):
            self._test_handle_subports_trunk_on_trunk_update(
                events.CREATED)

    def test_handle_subports_deleted_trunk_on_trunk_update(self):
        with mock.patch.object(
                self.skeleton.ovsdb_handler, 'unwire_subports_for_trunk'):
            self._test_handle_subports_trunk_on_trunk_update(
                events.DELETED)
