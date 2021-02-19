# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

from unittest import mock

from neutron.agent.linux import ip_conntrack
from neutron.tests import base


class IPConntrackTestCase(base.BaseTestCase):

    def setUp(self):
        super(IPConntrackTestCase, self).setUp()
        self.execute = mock.Mock()
        self.filtered_port = {}
        self.unfiltered_port = {}
        self.mgr = ip_conntrack.IpConntrackManager(
                     self._get_rule_for_table, self.filtered_port,
                     self.unfiltered_port, self.execute,
                     zone_per_port=True)

    def _get_rule_for_table(self, table):
        return ['test --physdev-in tapdevice -j CT --zone 100']

    def test_delete_conntrack_state_dedupes(self):
        rule = {'ethertype': 'IPv4', 'direction': 'ingress'}
        dev_info = {'device': 'tapdevice', 'fixed_ips': ['1.2.3.4']}
        dev_info_list = [dev_info for _ in range(10)]
        self.mgr._delete_conntrack_state(dev_info_list, rule)
        self.assertEqual(1, len(self.execute.mock_calls))


class OvsIPConntrackTestCase(IPConntrackTestCase):

    def setUp(self):
        super(IPConntrackTestCase, self).setUp()
        self.execute = mock.Mock()
        self.mgr = ip_conntrack.OvsIpConntrackManager(self.execute)

    def test_delete_conntrack_state_dedupes(self):
        rule = {'ethertype': 'IPv4', 'direction': 'ingress'}
        dev_info = {
            'device': 'tapdevice',
            'fixed_ips': ['1.2.3.4'],
            'of_port': mock.Mock(of_port=10)}
        dev_info_list = [dev_info for _ in range(10)]
        self.mgr._delete_conntrack_state(dev_info_list, rule)
        self.assertEqual(1, len(self.execute.mock_calls))

    def test_get_device_zone(self):
        of_port = mock.Mock(vlan_tag=10)
        port = {'id': 'port-id', 'of_port': of_port}
        self.assertEqual(10, self.mgr.get_device_zone(port))
