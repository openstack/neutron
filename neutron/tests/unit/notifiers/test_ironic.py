# Copyright (c) 2019 OpenStack Foundation.
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

import eventlet
import mock

from neutron_lib.api.definitions import portbindings as portbindings_def
from neutron_lib import constants as n_const
from openstack import connection
from openstack import exceptions as os_exc

from neutron.notifiers import batch_notifier
from neutron.notifiers import ironic
from neutron.tests import base


DEVICE_OWNER_BAREMETAL = n_const.DEVICE_OWNER_BAREMETAL_PREFIX + 'fake'


def get_fake_port():
    return {'id': '11111111-aaaa-bbbb-cccc-555555555555',
            'binding:host_id': '22222222-aaaa-bbbb-cccc-555555555555',
            'binding:vnic_type': portbindings_def.VNIC_BAREMETAL,
            'device_id': '22222222-aaaa-bbbb-cccc-555555555555',
            'mac_address': 'de:ad:ca:fe:ba:be'}


class TestIronicNotifier(base.BaseTestCase):
    def setUp(self):
        super(TestIronicNotifier, self).setUp()
        with mock.patch.object(connection.Connection, 'baremetal',
                               autospec=False):
            self.ironic_notifier = ironic.Notifier()

    @mock.patch.object(batch_notifier.BatchNotifier, 'queue_event',
                       autospec=True)
    def test_process_port_update_event_bind_port(self, mock_queue_event):
        port = get_fake_port()
        port.update({'status': n_const.PORT_STATUS_ACTIVE})
        original_port = get_fake_port()
        original_port.update({'status': n_const.PORT_STATUS_DOWN})
        self.ironic_notifier.process_port_update_event(
            'fake_resource', 'fake_event', 'fake_trigger',
            original_port=original_port, port=port, **{})
        mock_queue_event.assert_called_with(
            self.ironic_notifier.batch_notifier,
            {'event': 'network.bind_port',
             'binding:host_id': '22222222-aaaa-bbbb-cccc-555555555555',
             'binding:vnic_type': portbindings_def.VNIC_BAREMETAL,
             'device_id': '22222222-aaaa-bbbb-cccc-555555555555',
             'port_id': '11111111-aaaa-bbbb-cccc-555555555555',
             'mac_address': 'de:ad:ca:fe:ba:be',
             'status': n_const.PORT_STATUS_ACTIVE})

    @mock.patch.object(batch_notifier.BatchNotifier, 'queue_event',
                       autospec=True)
    def test_process_port_update_event_bind_port_err(self, mock_queue_event):
        port = get_fake_port()
        port.update({'status': n_const.PORT_STATUS_ERROR})
        original_port = get_fake_port()
        original_port.update({'status': n_const.PORT_STATUS_DOWN})
        self.ironic_notifier.process_port_update_event(
            'fake_resource', 'fake_event', 'fake_trigger',
            original_port=original_port, port=port, **{})
        mock_queue_event.assert_called_with(
            self.ironic_notifier.batch_notifier,
            {'event': 'network.bind_port',
             'binding:host_id': '22222222-aaaa-bbbb-cccc-555555555555',
             'binding:vnic_type': portbindings_def.VNIC_BAREMETAL,
             'device_id': '22222222-aaaa-bbbb-cccc-555555555555',
             'port_id': '11111111-aaaa-bbbb-cccc-555555555555',
             'mac_address': 'de:ad:ca:fe:ba:be',
             'status': n_const.PORT_STATUS_ERROR})

    @mock.patch.object(batch_notifier.BatchNotifier, 'queue_event',
                       autospec=True)
    def test_process_port_update_event_unbind_port(self, mock_queue_event):
        port = get_fake_port()
        port.update({'status': n_const.PORT_STATUS_DOWN})
        original_port = get_fake_port()
        original_port.update({'status': n_const.PORT_STATUS_ACTIVE})
        self.ironic_notifier.process_port_update_event(
            'fake_resource', 'fake_event', 'fake_trigger',
            original_port=original_port, port=port, **{})
        mock_queue_event.assert_called_with(
            self.ironic_notifier.batch_notifier,
            {'event': 'network.unbind_port',
             'binding:host_id': '22222222-aaaa-bbbb-cccc-555555555555',
             'binding:vnic_type': portbindings_def.VNIC_BAREMETAL,
             'device_id': '22222222-aaaa-bbbb-cccc-555555555555',
             'port_id': '11111111-aaaa-bbbb-cccc-555555555555',
             'mac_address': 'de:ad:ca:fe:ba:be',
             'status': n_const.PORT_STATUS_DOWN})

    @mock.patch.object(batch_notifier.BatchNotifier, 'queue_event',
                       autospec=True)
    def test_process_port_update_event_unbind_port_err(self, mock_queue_event):
        port = get_fake_port()
        port.update({'status': n_const.PORT_STATUS_ERROR})
        original_port = get_fake_port()
        original_port.update({'status': n_const.PORT_STATUS_ACTIVE})
        self.ironic_notifier.process_port_update_event(
            'fake_resource', 'fake_event', 'fake_trigger',
            original_port=original_port, port=port, **{})
        mock_queue_event.assert_called_with(
            self.ironic_notifier.batch_notifier,
            {'event': 'network.unbind_port',
             'binding:host_id': '22222222-aaaa-bbbb-cccc-555555555555',
             'binding:vnic_type': portbindings_def.VNIC_BAREMETAL,
             'device_id': '22222222-aaaa-bbbb-cccc-555555555555',
             'port_id': '11111111-aaaa-bbbb-cccc-555555555555',
             'mac_address': 'de:ad:ca:fe:ba:be',
             'status': n_const.PORT_STATUS_ERROR})

    @mock.patch.object(batch_notifier.BatchNotifier, 'queue_event',
                       autospec=True)
    def test_process_port_delete_event(self, mock_queue_event):
        port = get_fake_port()
        self.ironic_notifier.process_port_delete_event(
            'fake_resource', 'fake_event', 'fake_trigger', original_port=None,
            port=port, **{})
        mock_queue_event.assert_called_with(
            self.ironic_notifier.batch_notifier,
            {'event': 'network.delete_port',
             'binding:host_id': '22222222-aaaa-bbbb-cccc-555555555555',
             'binding:vnic_type': portbindings_def.VNIC_BAREMETAL,
             'device_id': '22222222-aaaa-bbbb-cccc-555555555555',
             'port_id': '11111111-aaaa-bbbb-cccc-555555555555',
             'mac_address': 'de:ad:ca:fe:ba:be',
             'status': 'DELETED'})

    @mock.patch.object(batch_notifier.BatchNotifier, 'queue_event',
                       autospec=True)
    def test_process_port_event_empty_uuid_field(self, mock_queue_event):
        port = get_fake_port()
        port.update({'device_id': ''})
        self.ironic_notifier.process_port_delete_event(
            'fake_resource', 'fake_event', 'fake_trigger', original_port=None,
            port=port, **{})
        mock_queue_event.assert_called_with(
            self.ironic_notifier.batch_notifier,
            {'event': 'network.delete_port',
             'binding:host_id': '22222222-aaaa-bbbb-cccc-555555555555',
             'binding:vnic_type': portbindings_def.VNIC_BAREMETAL,
             'port_id': '11111111-aaaa-bbbb-cccc-555555555555',
             'mac_address': 'de:ad:ca:fe:ba:be',
             'status': 'DELETED'})

    @mock.patch.object(eventlet, 'spawn_n', autospec=True)
    def test_queue_events(self, mock_spawn_n):
        port = get_fake_port()
        self.ironic_notifier.process_port_delete_event(
            'fake_resource', 'fake_event', 'fake_trigger', original_port=None,
            port=port, **{})

        port = get_fake_port()
        port.update({'status': n_const.PORT_STATUS_ACTIVE})
        original_port = get_fake_port()
        original_port.update({'status': n_const.PORT_STATUS_DOWN})
        self.ironic_notifier.process_port_update_event(
            'fake_resource', 'fake_event', 'fake_trigger',
            original_port=original_port, port=port, **{})

        self.assertEqual(
            2, len(self.ironic_notifier.batch_notifier._pending_events.queue))
        self.assertEqual(2, mock_spawn_n.call_count)

    @mock.patch.object(os_exc, 'raise_from_response', return_value=None)
    @mock.patch.object(connection.Connection, 'baremetal', autospec=True)
    def test_send_events(self, mock_client, mock_os_raise_exc):
        self.ironic_notifier.irclient = mock_client
        self.ironic_notifier.send_events(['test', 'events'])
        mock_client.post.assert_called_with(
            '/events', json={'events': ['test', 'events']},
            microversion='1.54')

    @mock.patch.object(ironic.LOG, 'exception', autospec=True)
    @mock.patch.object(connection.Connection, 'baremetal', autospec=True)
    def test_send_event_exception(self, mock_client, mock_log):
        self.ironic_notifier.irclient = mock_client
        mock_client.post.side_effect = Exception()
        self.ironic_notifier.send_events(['test', 'events'])
        self.assertEqual(1, mock_log.call_count)
