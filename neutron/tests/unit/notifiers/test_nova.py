# Copyright 2014 OpenStack Foundation
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

import queue
from unittest import mock

import eventlet
from keystoneauth1 import exceptions as ks_exc
from neutron_lib import constants as n_const
from neutron_lib import context as n_ctx
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from novaclient import api_versions
from novaclient import exceptions as nova_exceptions
from oslo_config import cfg
from oslo_utils import uuidutils
from sqlalchemy.orm import attributes as sql_attr

from neutron.notifiers import nova
from neutron.objects import ports as port_obj
from neutron.tests import base

DEVICE_OWNER_COMPUTE = n_const.DEVICE_OWNER_COMPUTE_PREFIX + 'fake'
DEVICE_OWNER_BAREMETAL = n_const.DEVICE_OWNER_BAREMETAL_PREFIX + 'fake'


class TestNovaNotify(base.BaseTestCase):
    def setUp(self, plugin=None):
        super(TestNovaNotify, self).setUp()
        self.ctx = n_ctx.get_admin_context()
        self.port_uuid = uuidutils.generate_uuid()

        class FakePlugin(object):
            def get_port(self, context, port_id):
                device_id = '32102d7b-1cf4-404d-b50a-97aae1f55f87'
                return {'device_id': device_id,
                        'device_owner': DEVICE_OWNER_COMPUTE,
                        'id': port_id}

        self.nova_notifier = nova.Notifier()
        directory.add_plugin(plugin_constants.CORE, FakePlugin())

    def test_notify_port_status_all_values(self):
        states = [n_const.PORT_STATUS_ACTIVE, n_const.PORT_STATUS_DOWN,
                  n_const.PORT_STATUS_ERROR, n_const.PORT_STATUS_BUILD,
                  None]
        device_id = '32102d7b-1cf4-404d-b50a-97aae1f55f87'
        # test all combinations
        for previous_port_status in states:
            for current_port_status in states:
                params = {'id': self.port_uuid, 'device_id': device_id,
                          'device_owner': DEVICE_OWNER_COMPUTE}
                if current_port_status:
                    params['status'] = current_port_status
                port = port_obj.Port(self.ctx, **params)
                self._record_port_status_changed_helper(current_port_status,
                                                        previous_port_status,
                                                        port)

    def test_port_without_uuid_device_id_no_notify(self):
        port = port_obj.Port(self.ctx, id=self.port_uuid,
                             device_id='compute_probe:',
                             device_owner=DEVICE_OWNER_COMPUTE,
                             status=n_const.PORT_STATUS_ACTIVE)
        self._record_port_status_changed_helper(n_const.PORT_STATUS_ACTIVE,
                                                sql_attr.NO_VALUE,
                                                port)

    def test_port_without_device_owner_no_notify(self):
        device_id = '32102d7b-1cf4-404d-b50a-97aae1f55f87'
        port = port_obj.Port(self.ctx, id=self.port_uuid, device_id=device_id,
                             device_owner="",
                             status=n_const.PORT_STATUS_ACTIVE)
        self._record_port_status_changed_helper(n_const.PORT_STATUS_ACTIVE,
                                                sql_attr.NO_VALUE,
                                                port)

    def test_port_without_device_id_no_notify(self):
        port = port_obj.Port(self.ctx, id=self.port_uuid, device_id="",
                             device_owner=n_const.DEVICE_OWNER_DHCP,
                             status=n_const.PORT_STATUS_ACTIVE)
        self._record_port_status_changed_helper(n_const.PORT_STATUS_ACTIVE,
                                                sql_attr.NO_VALUE,
                                                port)

    def test_non_compute_instances_no_notify(self):
        device_id = '32102d7b-1cf4-404d-b50a-97aae1f55f87'
        port = port_obj.Port(self.ctx, id=self.port_uuid, device_id=device_id,
                             device_owner=n_const.DEVICE_OWNER_DHCP,
                             status=n_const.PORT_STATUS_ACTIVE)
        self._record_port_status_changed_helper(n_const.PORT_STATUS_ACTIVE,
                                                sql_attr.NO_VALUE,
                                                port)

    def _record_port_status_changed_helper(self, current_port_status,
                                           previous_port_status, port):

        if not (port.device_id and port.id and port.device_owner and
                port.device_owner.startswith(
                    n_const.DEVICE_OWNER_COMPUTE_PREFIX) and
                uuidutils.is_uuid_like(port.device_id)):
            return

        if (previous_port_status == n_const.PORT_STATUS_ACTIVE and
                current_port_status == n_const.PORT_STATUS_DOWN):
            event_name = nova.VIF_UNPLUGGED

        elif (previous_port_status in [sql_attr.NO_VALUE,
                                       n_const.PORT_STATUS_DOWN,
                                       n_const.PORT_STATUS_BUILD] and
              current_port_status in [n_const.PORT_STATUS_ACTIVE,
                                      n_const.PORT_STATUS_ERROR]):
            event_name = nova.VIF_PLUGGED

        else:
            return

        status = nova.NEUTRON_NOVA_EVENT_STATUS_MAP.get(current_port_status)
        self.nova_notifier.record_port_status_changed(port,
                                                      current_port_status,
                                                      previous_port_status,
                                                      None)

        event = {'server_uuid': port.device_id, 'status': status,
                 'name': event_name, 'tag': self.port_uuid}
        self.assertEqual(event, port._notify_event)

    def test_update_fixed_ip_changed(self):
        device_id = '32102d7b-1cf4-404d-b50a-97aae1f55f87'
        returned_obj = {'port':
                        {'device_owner': DEVICE_OWNER_COMPUTE,
                         'id': 'bee50827-bcee-4cc8-91c1-a27b0ce54222',
                         'device_id': device_id}}

        expected_event = {'server_uuid': device_id,
                          'name': 'network-changed',
                          'tag': returned_obj['port']['id']}
        event = self.nova_notifier.create_port_changed_event('update_port',
                                                             {}, returned_obj)
        self.assertEqual(event, expected_event)

    def test_create_floatingip_notify(self):
        device_id = '32102d7b-1cf4-404d-b50a-97aae1f55f87'
        returned_obj = {'floatingip':
                        {'port_id': 'bee50827-bcee-4cc8-91c1-a27b0ce54222'}}

        expected_event = {'server_uuid': device_id,
                          'name': 'network-changed',
                          'tag': returned_obj['floatingip']['port_id']}
        event = self.nova_notifier.create_port_changed_event(
            'create_floatingip', {}, returned_obj)
        self.assertEqual(event, expected_event)

    def test_create_floatingip_no_port_id_no_notify(self):
        returned_obj = {'floatingip':
                        {'port_id': None}}

        event = self.nova_notifier.create_port_changed_event(
            'create_floatingip', {}, returned_obj)
        self.assertIsNone(event)

    def test_delete_floatingip_notify(self):
        device_id = '32102d7b-1cf4-404d-b50a-97aae1f55f87'
        returned_obj = {'floatingip':
                        {'port_id': 'bee50827-bcee-4cc8-91c1-a27b0ce54222'}}

        expected_event = {'server_uuid': device_id,
                          'name': 'network-changed',
                          'tag': returned_obj['floatingip']['port_id']}
        event = self.nova_notifier.create_port_changed_event(
            'delete_floatingip', {}, returned_obj)
        self.assertEqual(expected_event, event)

    def test_delete_floatingip_deleted_port_no_notify(self):
        port_id = 'bee50827-bcee-4cc8-91c1-a27b0ce54222'
        with mock.patch.object(directory.get_plugin(), 'get_port',
                side_effect=n_exc.PortNotFound(port_id=port_id)):
            returned_obj = {'floatingip':
                            {'port_id': port_id}}
            event = self.nova_notifier.create_port_changed_event(
                'delete_floatingip', {}, returned_obj)
            self.assertIsNone(event)

    def test_delete_floatingip_no_port_id_no_notify(self):
        returned_obj = {'floatingip':
                        {'port_id': None}}

        event = self.nova_notifier.create_port_changed_event(
            'delete_floatingip', {}, returned_obj)
        self.assertIsNone(event)

    def test_associate_floatingip_notify(self):
        device_id = '32102d7b-1cf4-404d-b50a-97aae1f55f87'
        returned_obj = {'floatingip':
                        {'port_id': '5a39def4-3d3f-473d-9ff4-8e90064b9cc1'}}
        original_obj = {'port_id': None}

        expected_event = {'server_uuid': device_id,
                          'name': 'network-changed',
                          'tag': returned_obj['floatingip']['port_id']}
        event = self.nova_notifier.create_port_changed_event(
            'update_floatingip', original_obj, returned_obj)
        self.assertEqual(expected_event, event)

    def test_disassociate_floatingip_notify(self):
        device_id = '32102d7b-1cf4-404d-b50a-97aae1f55f87'
        returned_obj = {'floatingip': {'port_id': None}}
        original_obj = {'port_id': '5a39def4-3d3f-473d-9ff4-8e90064b9cc1'}

        expected_event = {'server_uuid': device_id,
                          'name': 'network-changed',
                          'tag': original_obj['port_id']}

        event = self.nova_notifier.create_port_changed_event(
            'update_floatingip', original_obj, returned_obj)
        self.assertEqual(expected_event, event)

    def test_no_notification_notify_nova_on_port_data_changes_false(self):
        cfg.CONF.set_override('notify_nova_on_port_data_changes', False)

        with mock.patch.object(self.nova_notifier,
                               'send_events') as send_events:
            self.nova_notifier.send_network_change('update_floatingip',
                                                   {}, {})
            self.assertFalse(send_events.called)

    @mock.patch('novaclient.client.Client')
    def test_nova_send_events_noendpoint_invalidate_session(self, mock_client):
        create = mock_client().server_external_events.create
        create.side_effect = ks_exc.EndpointNotFound
        with mock.patch.object(self.nova_notifier.session,
                               'invalidate', return_value=True) as mock_sess:
            self.nova_notifier.send_events([])
            create.assert_called()
            mock_sess.assert_called()

    @mock.patch('novaclient.client.Client')
    def test_nova_send_events_returns_bad_list(self, mock_client):
        create = mock_client().server_external_events.create
        create.return_value = 'i am a string!'
        self.nova_notifier.send_events([])
        create.assert_called()

    @mock.patch('novaclient.client.Client')
    def test_nova_send_event_rasies_404(self, mock_client):
        create = mock_client().server_external_events.create
        create.return_value = nova_exceptions.NotFound
        self.nova_notifier.send_events([])
        create.assert_called()

    @mock.patch('novaclient.client.Client')
    def test_nova_send_events_raises_connect_exc(self, mock_client):
        create = mock_client().server_external_events.create
        create.side_effect = (
            ks_exc.ConnectFailure, ks_exc.ConnectTimeout, [])
        self.nova_notifier.send_events([])
        self.assertEqual(3, create.call_count)

    @mock.patch('novaclient.client.Client')
    def test_nova_send_events_raises(self, mock_client):
        create = mock_client().server_external_events.create
        create.return_value = Exception
        self.nova_notifier.send_events([])
        create.assert_called()

    @mock.patch('novaclient.client.Client')
    def test_nova_send_events_returns_non_200(self, mock_client):
        device_id = '32102d7b-1cf4-404d-b50a-97aae1f55f87'
        create = mock_client().server_external_events.create
        create.return_value = [
            {'code': 404,
             'name': 'network-changed',
             'server_uuid': device_id}]
        self.nova_notifier.send_events([{'name': 'network-changed',
                                         'server_uuid': device_id}])
        create.assert_called()

    @mock.patch('novaclient.client.Client')
    def test_nova_send_events_return_200(self, mock_client):
        device_id = '32102d7b-1cf4-404d-b50a-97aae1f55f87'
        create = mock_client().server_external_events.create
        create.return_value = [
            {'code': 200,
             'name': 'network-changed',
             'server_uuid': device_id}]
        self.nova_notifier.send_events([{'name': 'network-changed',
                                         'server_uuid': device_id}])
        create.assert_called()

    @mock.patch('novaclient.client.Client')
    def test_nova_send_events_multiple(self, mock_client):
        device_id = '32102d7b-1cf4-404d-b50a-97aae1f55f87'
        create = mock_client().server_external_events.create
        create.return_value = [
            {'code': 200,
             'name': 'network-changed',
             'server_uuid': device_id},
            {'code': 200,
             'name': 'network-changed',
             'server_uuid': device_id}]
        self.nova_notifier.send_events([
            {'name': 'network-changed', 'server_uuid': device_id},
            {'name': 'network-changed', 'server_uuid': device_id}])
        create.assert_called()

    def test_reassociate_floatingip_without_disassociate_event(self):
        returned_obj = {'floatingip':
                        {'port_id': 'f5348a16-609a-4971-b0f0-4b8def5235fb'}}
        original_obj = {'port_id': '5a39def4-3d3f-473d-9ff4-8e90064b9cc1'}
        self.nova_notifier._waiting_to_send = True
        self.nova_notifier.send_network_change(
            'update_floatingip', original_obj, returned_obj)
        self.assertEqual(
            2, len(self.nova_notifier.batch_notifier._pending_events.queue))

        returned_obj_non = {'floatingip': {'port_id': None}}
        event_dis = self.nova_notifier.create_port_changed_event(
            'update_floatingip', original_obj, returned_obj_non)
        event_assoc = self.nova_notifier.create_port_changed_event(
            'update_floatingip', original_obj, returned_obj)
        self.assertEqual(
            self.nova_notifier.batch_notifier._pending_events.get(), event_dis)
        self.assertEqual(
            self.nova_notifier.batch_notifier._pending_events.get(),
            event_assoc)

    def test_delete_port_notify(self):
        device_id = '32102d7b-1cf4-404d-b50a-97aae1f55f87'
        port_id = 'bee50827-bcee-4cc8-91c1-a27b0ce54222'
        returned_obj = {'port':
                        {'device_owner': DEVICE_OWNER_COMPUTE,
                         'id': port_id,
                         'device_id': device_id}}

        expected_event = {'server_uuid': device_id,
                          'name': nova.VIF_DELETED,
                          'tag': port_id}
        event = self.nova_notifier.create_port_changed_event('delete_port',
                                                             {}, returned_obj)
        self.assertEqual(expected_event, event)

    @mock.patch('novaclient.client.Client')
    def test_endpoint_types(self, mock_client):
        device_id = '32102d7b-1cf4-404d-b50a-97aae1f55f87'
        batched_events = [{'code': 200,
                           'name': 'network-changed',
                           'server_uuid': device_id}]
        response = [{'name': 'network-changed',
                     'server_uuid': device_id}]
        mock_client.server_external_events.create.return_value = (
            batched_events)
        self.nova_notifier.send_events(response)
        mock_client.assert_called_once_with(
            api_versions.APIVersion(nova.NOVA_API_VERSION),
            connect_retries=3,
            session=mock.ANY,
            region_name=cfg.CONF.nova.region_name,
            endpoint_type='public',
            extensions=mock.ANY,
            global_request_id=mock.ANY)

        mock_client.reset_mock()
        cfg.CONF.set_override('endpoint_type', 'internal', 'nova')
        mock_client.server_external_events.create.return_value = (
            batched_events)
        self.nova_notifier.send_events(response)
        mock_client.assert_called_once_with(
            api_versions.APIVersion(nova.NOVA_API_VERSION),
            connect_retries=3,
            session=mock.ANY,
            region_name=cfg.CONF.nova.region_name,
            endpoint_type='internal',
            extensions=mock.ANY,
            global_request_id=mock.ANY)

    def test_notify_port_active_direct(self):
        device_id = '32102d7b-1cf4-404d-b50a-97aae1f55f87'
        port_id = 'bee50827-bcee-4cc8-91c1-a27b0ce54222'
        port = port_obj.Port(self.ctx, id=port_id, device_id=device_id,
                             device_owner=DEVICE_OWNER_COMPUTE)
        expected_event = {'server_uuid': device_id,
                          'name': nova.VIF_PLUGGED,
                          'status': 'completed',
                          'tag': port_id}
        self.nova_notifier.notify_port_active_direct(port)

        self.assertEqual(
            1, len(self.nova_notifier.batch_notifier._pending_events.queue))
        self.assertEqual(
            expected_event,
            self.nova_notifier.batch_notifier._pending_events.get())

    def test_notify_concurrent_enable_flag_update(self):
        # This test assumes Neutron server uses eventlet.
        # NOTE(ralonsoh): the exceptions raise inside a thread won't stop the
        # test. The checks are stored in "_queue" and tested at the end of the
        # test execution.
        _queue = eventlet.queue.Queue()

        def _local_executor(thread_idx):
            # This thread has not yet initialized the local "enable" flag.
            _queue.put(getattr(nova._notifier_store, 'enable', None) is None)
            eventlet.sleep(0)  # Next thread execution.
            new_enable = bool(thread_idx % 2)
            with self.nova_notifier.context_enabled(new_enable):
                # At this point, the Nova Notifier should have updated the
                # "enable" flag.
                _queue.put(new_enable == nova._notifier_store.enable)
                eventlet.sleep(0)  # Next thread execution.
                _queue.put(new_enable == nova._notifier_store.enable)
            _queue.put(nova.NOTIFIER_ENABLE_DEFAULT ==
                       nova._notifier_store.enable)

        num_threads = 20
        pool = eventlet.GreenPool(num_threads)
        for idx in range(num_threads):
            pool.spawn(_local_executor, idx)
        pool.waitall()
        try:
            while True:
                self.assertTrue(_queue.get(block=False))
        except queue.Empty:
            pass
