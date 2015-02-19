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

from neutron.agent.linux import async_process
from neutron.agent.linux import ip_monitor
from neutron.tests.functional.agent.linux import test_ip_lib


class TestIPMonitor(test_ip_lib.IpLibTestFramework):
    def setUp(self):
        super(TestIPMonitor, self).setUp()
        attr = self.generate_device_details()
        self.device = self.manage_device(attr)
        self.monitor = ip_monitor.IPMonitor(attr.namespace)
        self.addCleanup(self._safe_stop_monitor)

    def _safe_stop_monitor(self):
        try:
            self.monitor.stop()
        except async_process.AsyncProcessException:
            pass

    def test_ip_monitor_lifecycle(self):
        self.assertFalse(self.monitor.is_active())
        self.monitor.start()
        self.assertTrue(self.monitor.is_active())
        self.monitor.stop()
        self.assertFalse(self.monitor.is_active())

    def test_ip_monitor_events(self):
        self.monitor.start()

        cidr = '169.254.128.1/24'
        self.device.addr.add(cidr)
        self._assert_event(expected_name=self.device.name,
                           expected_cidr=cidr,
                           expected_added=True,
                           event=ip_monitor.IPMonitorEvent.from_text(
                               next(self.monitor.iter_stdout(block=True))))

        self.device.addr.delete(cidr)
        self._assert_event(expected_name=self.device.name,
                           expected_cidr=cidr,
                           expected_added=False,
                           event=ip_monitor.IPMonitorEvent.from_text(
                               next(self.monitor.iter_stdout(block=True))))

    def _assert_event(self,
                      expected_name,
                      expected_cidr,
                      expected_added,
                      event):
        self.assertEqual(expected_name, event.interface)
        self.assertEqual(expected_added, event.added)
        self.assertEqual(expected_cidr, event.cidr)
