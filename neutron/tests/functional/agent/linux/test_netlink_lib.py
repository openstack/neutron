# Copyright (c) 2017 Fujitsu Limited
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

from neutron.agent.linux import utils as linux_utils
from neutron.privileged.agent.linux import netlink_lib as nl_lib
from neutron.tests.functional import base as functional_base


class NetlinkLibTestCase(functional_base.BaseSudoTestCase):
    """Functional test for netlink_lib: List, delete, flush conntrack entries.

    For each function, first we add a specific namespace, then create real
    conntrack entries. netlink_lib function will do list, delete and flush
    these entries. This class will test this netlink_lib function work
    as expected.
    """

    def _create_entries(self, zone):
        conntrack_cmds = (
            ['conntrack', '-I', '-p', 'tcp',
             '-s', '1.1.1.1', '-d', '2.2.2.2',
             '--sport', '1', '--dport', '2',
             '--state', 'ESTABLISHED', '--timeout', '1234', '-w', zone],
            ['conntrack', '-I', '-p', 'udp',
             '-s', '1.1.1.1', '-d', '2.2.2.2',
             '--sport', '4', '--dport', '5',
             '--timeout', '1234', '-w', zone],
            ['conntrack', '-I', '-p', 'icmp',
             '-s', '1.1.1.1', '-d', '2.2.2.2',
             '--icmp-type', '8', '--icmp-code', '0', '--icmp-id', '3333',
             '--timeout', '1234', '-w', zone],
        )

        for cmd in conntrack_cmds:
            try:
                linux_utils.execute(
                    cmd, run_as_root=True, check_exit_code=True,
                    privsep_exec=True, extra_ok_codes=[1])
            except RuntimeError:
                raise Exception('Error while creating entry')

    def _delete_entry(self, delete_entries, remain_entries, zone):
        nl_lib.delete_entries(entries=delete_entries)
        entries_list = nl_lib.list_entries(zone=zone)
        for delete_entry in delete_entries:
            self.assertNotIn(delete_entry, entries_list)
        for remain_entry in remain_entries:
            self.assertIn(remain_entry, entries_list)

    @staticmethod
    def _find_unused_zone_id(start, end):
        """Find unused zone ID starting from a specified ID"""
        while start <= end:
            cmd = ['conntrack', '-L', '-w', start]
            try:
                current_entries = linux_utils.execute(
                    cmd, run_as_root=True, check_exit_code=True,
                    privsep_exec=True, extra_ok_codes=[1])
            except RuntimeError:
                raise Exception('Error while listing entries')
            if not current_entries:
                return start
            start += 1
        raise Exception("Can not find usable zone_id")

    def test_list_entries(self):
        _zone = self._find_unused_zone_id(10, 30)
        self._create_entries(zone=_zone)
        expected = (
            (4, 'icmp', 8, 0, '1.1.1.1', '2.2.2.2', 3333, _zone),
            (4, 'tcp', 1, 2, '1.1.1.1', '2.2.2.2', _zone),
            (4, 'udp', 4, 5, '1.1.1.1', '2.2.2.2', _zone)
        )
        entries_list = nl_lib.list_entries(zone=_zone)
        for entry in expected:
            self.assertIn(entry, entries_list)

    def test_delete_icmp_entry(self):
        _zone = self._find_unused_zone_id(31, 50)
        self._create_entries(zone=_zone)
        icmp_entry = [(4, 'icmp', 8, 0, '1.1.1.1', '2.2.2.2', 3333, _zone)]
        remain_entries = (
            (4, 'tcp', 1, 2, '1.1.1.1', '2.2.2.2', _zone),
            (4, 'udp', 4, 5, '1.1.1.1', '2.2.2.2', _zone),
        )
        self._delete_entry(icmp_entry, remain_entries, _zone)

    def test_delete_tcp_entry(self):
        _zone = self._find_unused_zone_id(51, 70)
        self._create_entries(zone=_zone)
        tcp_entry = [(4, 'tcp', 1, 2, '1.1.1.1', '2.2.2.2', _zone)]
        remain_entries = (
            (4, 'icmp', 8, 0, '1.1.1.1', '2.2.2.2', 3333, _zone),
            (4, 'udp', 4, 5, '1.1.1.1', '2.2.2.2', _zone)
        )
        self._delete_entry(tcp_entry, remain_entries, _zone)

    def test_delete_udp_entry(self):
        _zone = self._find_unused_zone_id(71, 90)
        self._create_entries(zone=_zone)
        udp_entry = [(4, 'udp', 4, 5, '1.1.1.1', '2.2.2.2', _zone)]
        remain_entries = (
            (4, 'icmp', 8, 0, '1.1.1.1', '2.2.2.2', 3333, _zone),
            (4, 'tcp', 1, 2, '1.1.1.1', '2.2.2.2', _zone)
        )
        self._delete_entry(udp_entry, remain_entries, _zone)

    def test_delete_multiple_entries(self):
        _zone = self._find_unused_zone_id(91, 110)
        self._create_entries(zone=_zone)
        delete_entries = (
            (4, 'icmp', 8, 0, '1.1.1.1', '2.2.2.2', 3333, _zone),
            (4, 'tcp', 1, 2, '1.1.1.1', '2.2.2.2', _zone),
            (4, 'udp', 4, 5, '1.1.1.1', '2.2.2.2', _zone)
        )
        remain_entries = ()
        self._delete_entry(delete_entries, remain_entries, _zone)
