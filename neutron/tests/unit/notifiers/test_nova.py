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


import mock
from novaclient import exceptions as nova_exceptions
from sqlalchemy.orm import attributes as sql_attr

from oslo_config import cfg

from neutron.common import constants
from neutron.db import models_v2
from neutron.notifiers import nova
from neutron.openstack.common import uuidutils
from neutron.tests import base


class TestNovaNotify(base.BaseTestCase):
    def setUp(self, plugin=None):
        super(TestNovaNotify, self).setUp()

        class FakePlugin(object):
            def get_port(self, context, port_id):
                device_id = '32102d7b-1cf4-404d-b50a-97aae1f55f87'
                return {'device_id': device_id,
                        'device_owner': 'compute:None'}

        self.nova_notifier = nova.Notifier()
        self.nova_notifier._plugin_ref = FakePlugin()

    def test_notify_port_status_all_values(self):
        states = [constants.PORT_STATUS_ACTIVE, constants.PORT_STATUS_DOWN,
                  constants.PORT_STATUS_ERROR, constants.PORT_STATUS_BUILD,
                  sql_attr.NO_VALUE]
        device_id = '32102d7b-1cf4-404d-b50a-97aae1f55f87'
        # test all combinations
        for previous_port_status in states:
            for current_port_status in states:

                port = models_v2.Port(id='port-uuid', device_id=device_id,
                                      device_owner="compute:",
                                      status=current_port_status)
                self._record_port_status_changed_helper(current_port_status,
                                                        previous_port_status,
                                                        port)

    def test_port_without_uuid_device_id_no_notify(self):
        port = models_v2.Port(id='port-uuid', device_id='compute_probe:',
                              device_owner='compute:',
                              status=constants.PORT_STATUS_ACTIVE)
        self._record_port_status_changed_helper(constants.PORT_STATUS_ACTIVE,
                                                sql_attr.NO_VALUE,
                                                port)

    def test_port_without_device_owner_no_notify(self):
        device_id = '32102d7b-1cf4-404d-b50a-97aae1f55f87'
        port = models_v2.Port(id='port-uuid', device_id=device_id,
                              status=constants.PORT_STATUS_ACTIVE)
        self._record_port_status_changed_helper(constants.PORT_STATUS_ACTIVE,
                                                sql_attr.NO_VALUE,
                                                port)

    def test_port_without_device_id_no_notify(self):
        port = models_v2.Port(id='port-uuid', device_owner="network:dhcp",
                              status=constants.PORT_STATUS_ACTIVE)
        self._record_port_status_changed_helper(constants.PORT_STATUS_ACTIVE,
                                                sql_attr.NO_VALUE,
                                                port)

    def test_port_without_id_no_notify(self):
        device_id = '32102d7b-1cf4-404d-b50a-97aae1f55f87'
        port = models_v2.Port(device_id=device_id,
                              device_owner="compute:",
                              status=constants.PORT_STATUS_ACTIVE)
        self._record_port_status_changed_helper(constants.PORT_STATUS_ACTIVE,
                                                sql_attr.NO_VALUE,
                                                port)

    def test_non_compute_instances_no_notify(self):
        device_id = '32102d7b-1cf4-404d-b50a-97aae1f55f87'
        port = models_v2.Port(id='port-uuid', device_id=device_id,
                              device_owner="network:dhcp",
                              status=constants.PORT_STATUS_ACTIVE)
        self._record_port_status_changed_helper(constants.PORT_STATUS_ACTIVE,
                                                sql_attr.NO_VALUE,
                                                port)

    def _record_port_status_changed_helper(self, current_port_status,
                                           previous_port_status, port):

        if not (port.device_id and port.id and port.device_owner and
                port.device_owner.startswith('compute:') and
                uuidutils.is_uuid_like(port.device_id)):
            return

        if (previous_port_status == constants.PORT_STATUS_ACTIVE and
                current_port_status == constants.PORT_STATUS_DOWN):
            event_name = nova.VIF_UNPLUGGED

        elif (previous_port_status in [sql_attr.NO_VALUE,
                                       constants.PORT_STATUS_DOWN,
                                       constants.PORT_STATUS_BUILD]
              and current_port_status in [constants.PORT_STATUS_ACTIVE,
                                          constants.PORT_STATUS_ERROR]):
            event_name = nova.VIF_PLUGGED

        else:
            return

        status = nova.NEUTRON_NOVA_EVENT_STATUS_MAP.get(current_port_status)
        self.nova_notifier.record_port_status_changed(port,
                                                      current_port_status,
                                                      previous_port_status,
                                                      None)

        event = {'server_uuid': port.device_id, 'status': status,
                 'name': event_name, 'tag': 'port-uuid'}
        self.assertEqual(event, port._notify_event)

    def test_update_fixed_ip_changed(self):
        device_id = '32102d7b-1cf4-404d-b50a-97aae1f55f87'
        returned_obj = {'port':
                        {'device_owner': u'compute:dfd',
                         'id': u'bee50827-bcee-4cc8-91c1-a27b0ce54222',
                         'device_id': device_id}}

        expected_event = {'server_uuid': device_id,
                          'name': 'network-changed'}
        event = self.nova_notifier.create_port_changed_event('update_port',
                                                             {}, returned_obj)
        self.assertEqual(event, expected_event)

    def test_create_floatingip_notify(self):
        device_id = '32102d7b-1cf4-404d-b50a-97aae1f55f87'
        returned_obj = {'floatingip':
                        {'port_id': u'bee50827-bcee-4cc8-91c1-a27b0ce54222'}}

        expected_event = {'server_uuid': device_id,
                          'name': 'network-changed'}
        event = self.nova_notifier.create_port_changed_event(
            'create_floatingip', {}, returned_obj)
        self.assertEqual(event, expected_event)

    def test_create_floatingip_no_port_id_no_notify(self):
        returned_obj = {'floatingip':
                        {'port_id': None}}

        event = self.nova_notifier.create_port_changed_event(
            'create_floatingip', {}, returned_obj)
        self.assertFalse(event, None)

    def test_delete_floatingip_notify(self):
        device_id = '32102d7b-1cf4-404d-b50a-97aae1f55f87'
        returned_obj = {'floatingip':
                        {'port_id': u'bee50827-bcee-4cc8-91c1-a27b0ce54222'}}

        expected_event = {'server_uuid': device_id,
                          'name': 'network-changed'}
        event = self.nova_notifier.create_port_changed_event(
            'delete_floatingip', {}, returned_obj)
        self.assertEqual(expected_event, event)

    def test_delete_floatingip_no_port_id_no_notify(self):
        returned_obj = {'floatingip':
                        {'port_id': None}}

        event = self.nova_notifier.create_port_changed_event(
            'delete_floatingip', {}, returned_obj)
        self.assertEqual(event, None)

    def test_associate_floatingip_notify(self):
        device_id = '32102d7b-1cf4-404d-b50a-97aae1f55f87'
        returned_obj = {'floatingip':
                        {'port_id': u'5a39def4-3d3f-473d-9ff4-8e90064b9cc1'}}
        original_obj = {'port_id': None}

        expected_event = {'server_uuid': device_id,
                          'name': 'network-changed'}
        event = self.nova_notifier.create_port_changed_event(
            'update_floatingip', original_obj, returned_obj)
        self.assertEqual(expected_event, event)

    def test_disassociate_floatingip_notify(self):
        device_id = '32102d7b-1cf4-404d-b50a-97aae1f55f87'
        returned_obj = {'floatingip': {'port_id': None}}
        original_obj = {'port_id': '5a39def4-3d3f-473d-9ff4-8e90064b9cc1'}

        expected_event = {'server_uuid': device_id,
                          'name': 'network-changed'}

        event = self.nova_notifier.create_port_changed_event(
            'update_floatingip', original_obj, returned_obj)
        self.assertEqual(expected_event, event)

    def test_no_notification_notify_nova_on_port_data_changes_false(self):
        cfg.CONF.set_override('notify_nova_on_port_data_changes', False)

        with mock.patch.object(self.nova_notifier,
                               'send_events') as send_events:
            self.nova_notifier.send_network_change('update_floatingip',
                                                   {}, {})
            self.assertFalse(send_events.called, False)

    def test_nova_send_events_returns_bad_list(self):
        with mock.patch.object(
            self.nova_notifier.nclient.server_external_events,
                'create') as nclient_create:
            nclient_create.return_value = 'i am a string!'
            self.nova_notifier.send_events([])

    def test_nova_send_event_rasies_404(self):
        with mock.patch.object(
            self.nova_notifier.nclient.server_external_events,
                'create') as nclient_create:
            nclient_create.side_effect = nova_exceptions.NotFound
            self.nova_notifier.send_events([])

    def test_nova_send_events_raises(self):
        with mock.patch.object(
            self.nova_notifier.nclient.server_external_events,
                'create') as nclient_create:
            nclient_create.side_effect = Exception
            self.nova_notifier.send_events([])

    def test_nova_send_events_returns_non_200(self):
        device_id = '32102d7b-1cf4-404d-b50a-97aae1f55f87'
        with mock.patch.object(
            self.nova_notifier.nclient.server_external_events,
                'create') as nclient_create:
            nclient_create.return_value = [{'code': 404,
                                            'name': 'network-changed',
                                            'server_uuid': device_id}]
            self.nova_notifier.send_events(
                [{'name': 'network-changed', 'server_uuid': device_id}])

    def test_nova_send_events_return_200(self):
        device_id = '32102d7b-1cf4-404d-b50a-97aae1f55f87'
        with mock.patch.object(
            self.nova_notifier.nclient.server_external_events,
                'create') as nclient_create:
            nclient_create.return_value = [{'code': 200,
                                            'name': 'network-changed',
                                            'server_uuid': device_id}]
            self.nova_notifier.send_events(
                [{'name': 'network-changed', 'server_uuid': device_id}])

    def test_nova_send_events_multiple(self):
        device_id = '32102d7b-1cf4-404d-b50a-97aae1f55f87'
        with mock.patch.object(
            self.nova_notifier.nclient.server_external_events,
                'create') as nclient_create:
            nclient_create.return_value = [{'code': 200,
                                            'name': 'network-changed',
                                            'server_uuid': device_id},
                                           {'code': 200,
                                            'name': 'network-changed',
                                            'server_uuid': device_id}]
            self.nova_notifier.send_events([
                {'name': 'network-changed', 'server_uuid': device_id},
                {'name': 'network-changed', 'server_uuid': device_id}])

    def test_reassociate_floatingip_without_disassociate_event(self):
        returned_obj = {'floatingip':
                        {'port_id': 'f5348a16-609a-4971-b0f0-4b8def5235fb'}}
        original_obj = {'port_id': '5a39def4-3d3f-473d-9ff4-8e90064b9cc1'}
        self.nova_notifier._waiting_to_send = True
        self.nova_notifier.send_network_change(
            'update_floatingip', original_obj, returned_obj)
        self.assertEqual(
            2, len(self.nova_notifier.batch_notifier.pending_events))

        returned_obj_non = {'floatingip': {'port_id': None}}
        event_dis = self.nova_notifier.create_port_changed_event(
            'update_floatingip', original_obj, returned_obj_non)
        event_assoc = self.nova_notifier.create_port_changed_event(
            'update_floatingip', original_obj, returned_obj)
        self.assertEqual(
            self.nova_notifier.batch_notifier.pending_events[0], event_dis)
        self.assertEqual(
            self.nova_notifier.batch_notifier.pending_events[1], event_assoc)
