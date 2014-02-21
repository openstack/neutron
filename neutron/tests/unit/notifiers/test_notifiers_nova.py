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


from sqlalchemy.orm import attributes as sql_attr

from neutron.common import constants
from neutron.db import models_v2
from neutron.notifiers import nova
from neutron.tests import base


class TestNovaNotify(base.BaseTestCase):
    def setUp(self, plugin=None):
        super(TestNovaNotify, self).setUp()

        self.nova_notifier = nova.Notifier()

    def test_notify_port_status_all_values(self):
        states = [constants.PORT_STATUS_ACTIVE, constants.PORT_STATUS_DOWN,
                  constants.PORT_STATUS_ERROR, constants.PORT_STATUS_BUILD,
                  sql_attr.NO_VALUE]
        # test all combinations
        for previous_port_status in states:
            for current_port_status in states:
                port = models_v2.Port(id='port-uuid', device_id='device-uuid',
                                      device_owner="compute:",
                                      status=current_port_status)
                self._record_port_status_changed_helper(current_port_status,
                                                        previous_port_status,
                                                        port)

    def test_port_without_device_owner_no_notify(self):
        port = models_v2.Port(id='port-uuid', device_id='device-uuid',
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
        port = models_v2.Port(device_id='device-uuid',
                              device_owner="compute:",
                              status=constants.PORT_STATUS_ACTIVE)
        self._record_port_status_changed_helper(constants.PORT_STATUS_ACTIVE,
                                                sql_attr.NO_VALUE,
                                                port)

    def test_non_compute_instances_no_notify(self):
        port = models_v2.Port(id='port-uuid', device_id='device-uuid',
                              device_owner="network:dhcp",
                              status=constants.PORT_STATUS_ACTIVE)
        self._record_port_status_changed_helper(constants.PORT_STATUS_ACTIVE,
                                                sql_attr.NO_VALUE,
                                                port)

    def _record_port_status_changed_helper(self, current_port_status,
                                           previous_port_status, port):

        if not (port.device_id and port.id and port.device_owner and
                port.device_owner.startswith('compute:')):
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

        event = {'server_uuid': 'device-uuid', 'status': status,
                 'name': event_name, 'tag': 'port-uuid'}
        self.assertEqual(event, port._notify_event)
