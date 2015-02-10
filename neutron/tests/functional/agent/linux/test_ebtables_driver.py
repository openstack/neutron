# Copyright (c) 2015 OpenStack Foundation.
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

from neutron.agent.linux import ebtables_driver
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils as linux_utils
from neutron.tests.functional.agent.linux import base
from neutron.tests.functional.agent.linux import helpers


NO_FILTER_APPLY = (
    "*filter\n"
    ":INPUT ACCEPT\n"
    ":FORWARD ACCEPT\n"
    ":OUTPUT ACCEPT\n"
    ":neutron-nwfilter-OUTPUT ACCEPT\n"
    ":neutron-nwfilter-INPUT ACCEPT\n"
    ":neutron-nwfilter-FORWARD ACCEPT\n"
    ":neutron-nwfilter-spoofing-fallb ACCEPT\n"
    "[0:0] -A INPUT -j neutron-nwfilter-INPUT\n"
    "[0:0] -A FORWARD -j neutron-nwfilter-FORWARD\n"
    "[2:140] -A OUTPUT -j neutron-nwfilter-OUTPUT\n"
    "[0:0] -A neutron-nwfilter-spoofing-fallb -j DROP\n"
    "COMMIT")

FILTER_APPLY_TEMPLATE = (
    "*filter\n"
    ":INPUT ACCEPT\n"
    ":FORWARD ACCEPT\n"
    ":OUTPUT ACCEPT\n"
    ":neutron-nwfilter-OUTPUT ACCEPT\n"
    ":neutron-nwfilter-isome-port-id ACCEPT\n"
    ":neutron-nwfilter-i-arp-some-por ACCEPT\n"
    ":neutron-nwfilter-i-ip-some-port ACCEPT\n"
    ":neutron-nwfilter-spoofing-fallb ACCEPT\n"
    ":neutron-nwfilter-INPUT ACCEPT\n"
    ":neutron-nwfilter-FORWARD ACCEPT\n"
    "[0:0] -A neutron-nwfilter-OUTPUT -j neutron-nwfilter-isome-port-id\n"
    "[0:0] -A INPUT -j neutron-nwfilter-INPUT\n"
    "[2:140] -A OUTPUT -j neutron-nwfilter-OUTPUT\n"
    "[0:0] -A FORWARD -j neutron-nwfilter-FORWARD\n"
    "[0:0] -A neutron-nwfilter-spoofing-fallb -j DROP\n"
    "[0:0] -A neutron-nwfilter-i-arp-some-por "
    "-p arp --arp-opcode 2 --arp-mac-src %(mac_addr)s "
    "--arp-ip-src %(ip_addr)s -j RETURN\n"
    "[0:0] -A neutron-nwfilter-i-arp-some-por -p ARP --arp-op Request "
    "-j ACCEPT\n"
    "[0:0] -A neutron-nwfilter-i-arp-some-por "
    "-j neutron-nwfilter-spoofing-fallb\n"
    "[0:0] -A neutron-nwfilter-isome-port-id "
    "-p arp -j neutron-nwfilter-i-arp-some-por\n"
    "[0:0] -A neutron-nwfilter-i-ip-some-port "
    "-s %(mac_addr)s -p IPv4 --ip-source %(ip_addr)s -j RETURN\n"
    "[0:0] -A neutron-nwfilter-i-ip-some-port "
    "-j neutron-nwfilter-spoofing-fallb\n"
    "[0:0] -A neutron-nwfilter-isome-port-id "
    "-p IPv4 -j neutron-nwfilter-i-ip-some-port\n"
    "COMMIT")


class EbtablesLowLevelTestCase(base.BaseIPVethTestCase):

    def setUp(self):
        super(EbtablesLowLevelTestCase, self).setUp()
        self.src_ns, self.dst_ns = self.prepare_veth_pairs()
        devs = [d for d in self.src_ns.get_devices() if d.name != "lo"]
        src_dev_name = devs[0].name
        self.ns = self.src_ns.namespace
        self.execute = linux_utils.execute
        self.pinger = helpers.Pinger(self.src_ns)

        # Extract MAC and IP address of one of my interfaces
        self.mac = self.src_ns.device(src_dev_name).link.address
        addr = [a for a in
                self.src_ns.device(src_dev_name).addr.list()][0]['cidr']
        self.addr = addr.split("/")[0]

        # Pick one of the namespaces and setup a bridge for the local ethernet
        # interface there, because ebtables only works on bridged interfaces.
        self.src_ns.netns.execute("brctl addbr mybridge".split())
        self.src_ns.netns.execute(("brctl addif mybridge %s" % src_dev_name).
                                  split())

        # Take the IP addrss off one of the interfaces and apply it to the
        # bridge interface instead.
        dev_source = ip_lib.IPDevice(src_dev_name, self.src_ns.namespace)
        dev_mybridge = ip_lib.IPDevice("mybridge", self.src_ns.namespace)
        dev_source.addr.delete(addr)
        dev_mybridge.link.set_up()
        dev_mybridge.addr.add(addr)

    def _test_basic_port_filter_wrong_mac(self):
        # Setup filter with wrong IP/MAC address pair. Basic filters only allow
        # packets with specified address combinations, thus all packets will
        # be dropped.
        mac_ip_pair = dict(mac_addr="11:11:11:22:22:22", ip_addr=self.addr)
        filter_apply = FILTER_APPLY_TEMPLATE % mac_ip_pair
        ebtables_driver.ebtables_restore(filter_apply,
                                         self.execute,
                                         self.ns)
        self.pinger.assert_no_ping(self.DST_ADDRESS)

        # Assure that ping will work once we unfilter the instance
        ebtables_driver.ebtables_restore(NO_FILTER_APPLY,
                                         self.execute,
                                         self.ns)
        self.pinger.assert_ping(self.DST_ADDRESS)

    def _test_basic_port_filter_correct_mac(self):
        # Use the correct IP/MAC address pair for this one.
        mac_ip_pair = dict(mac_addr=self.mac, ip_addr=self.addr)

        filter_apply = FILTER_APPLY_TEMPLATE % mac_ip_pair
        ebtables_driver.ebtables_restore(filter_apply,
                                         self.execute,
                                         self.ns)

        self.pinger.assert_ping(self.DST_ADDRESS)

    def test_ebtables_filtering(self):
        # Cannot parallelize those tests. Therefore need to call them
        # in order from a single function.
        self._test_basic_port_filter_wrong_mac()
        self._test_basic_port_filter_correct_mac()
