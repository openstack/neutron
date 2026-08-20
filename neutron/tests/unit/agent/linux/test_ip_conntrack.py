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
        super().setUp()
        self.execute = mock.Mock()
        self.filtered_port = {}
        self.unfiltered_port = {}
        mock.patch.object(ip_conntrack.IpConntrackManager,
                          '_process_queue_worker').start()
        self.mgr = ip_conntrack.IpConntrackManager(
                     self._get_rule_for_table, self.filtered_port,
                     self.unfiltered_port, self.execute,
                     zone_per_port=True)

    def _get_rule_for_table(self, table):
        # "tapdevice" is the interface name; the port/device id encoded in
        # it (after stripping the "tap" prefix) is "device"
        return ['test --physdev-in tapdevice -j CT --zone 100']

    def test_delete_conntrack_state_dedupes(self):
        rule = {'ethertype': 'IPv4', 'direction': 'ingress'}
        # port['device'] is the port id, not the interface name.
        dev_info = {'device': 'device', 'fixed_ips': ['1.2.3.4']}
        dev_info_list = [dev_info for _ in range(10)]
        self.mgr._delete_conntrack_state(dev_info_list, rule)
        self.assertEqual(1, len(self.execute.mock_calls))


class IPConntrackZonePerPortRestoreTestCase(base.BaseTestCase):
    """Regression test for bug where zones are not restored after restart.

    port['device'] is the full port id, not an interface name, so
    _device_key() must not strip a fake interface-name prefix off of it;
    otherwise it never matches the key _populate_initial_zone_map() derives
    from the on-disk iptables rules, and every restart hands out a brand
    new zone for already-existing ports.
    """

    def test_zone_restored_across_restart(self):
        # avoid actually running the background queue-processing thread;
        # this test only exercises the zone restore/lookup logic.
        mock.patch.object(ip_conntrack.IpConntrackManager,
                          '_process_queue_worker').start()

        port_id = '12345678-1234-5678-1234-567812345678'
        # the interface names actually programmed on the host truncate the
        # id to fit the Linux 14-char ifname limit, e.g. "tap"/"qvb" + 11
        # chars of the id.
        short_id = port_id[:11]

        def get_rules(table):
            return ['test --physdev-in tap%s -j CT --zone 100' % short_id]

        mgr = ip_conntrack.IpConntrackManager(
            get_rules, {}, {}, mock.Mock(), zone_per_port=True)

        port = {'device': port_id, 'fixed_ips': ['1.2.3.4']}
        # after a restart, the zone previously used for this port must be
        # found again instead of a new one being allocated.
        self.assertEqual(100, mgr.get_device_zone(port, create=False))


class OvsIPConntrackTestCase(IPConntrackTestCase):

    def setUp(self):
        super(IPConntrackTestCase, self).setUp()
        self.execute = mock.Mock()
        mock.patch.object(ip_conntrack.IpConntrackManager,
                          '_process_queue_worker').start()
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
