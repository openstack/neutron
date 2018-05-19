# Copyright 2015 Red Hat, Inc.
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

from neutron.agent.linux import ip_monitor
from neutron.tests import base


class TestIPMonitorEvent(base.BaseTestCase):
    def test_from_text_parses_added_line(self):
        event = ip_monitor.IPMonitorEvent.from_text(
            '3: wlp3s0    inet 192.168.3.59/24 brd 192.168.3.255 '
            r'scope global dynamic wlp3s0\       valid_lft 300sec '
            'preferred_lft 300sec')
        self.assertEqual('wlp3s0', event.interface)
        self.assertTrue(event.added)
        self.assertEqual('192.168.3.59/24', event.cidr)

    def test_from_text_parses_deleted_line(self):
        event = ip_monitor.IPMonitorEvent.from_text(
            'Deleted 1: lo    inet 127.0.0.2/8 scope host secondary lo\''
            '       valid_lft forever preferred_lft forever')
        self.assertEqual('lo', event.interface)
        self.assertFalse(event.added)
        self.assertEqual('127.0.0.2/8', event.cidr)
