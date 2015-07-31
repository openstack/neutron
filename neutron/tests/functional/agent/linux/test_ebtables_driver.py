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

from neutron.agent.linux import bridge_lib
from neutron.agent.linux import ebtables_driver
from neutron.tests.common import machine_fixtures
from neutron.tests.common import net_helpers
from neutron.tests.functional import base


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


class EbtablesLowLevelTestCase(base.BaseSudoTestCase):

    def setUp(self):
        super(EbtablesLowLevelTestCase, self).setUp()

        bridge = self.useFixture(net_helpers.VethBridgeFixture()).bridge
        self.source, self.destination = self.useFixture(
            machine_fixtures.PeerMachines(bridge)).machines

        # Extract MAC and IP address of one of my interfaces
        self.mac = self.source.port.link.address
        self.addr = self.source.ip

        # Pick one of the namespaces and setup a bridge for the local ethernet
        # interface there, because ebtables only works on bridged interfaces.
        dev_mybridge = bridge_lib.BridgeDevice.addbr(
            'mybridge', self.source.namespace)
        dev_mybridge.addif(self.source.port.name)

        # Take the IP addrss off one of the interfaces and apply it to the
        # bridge interface instead.
        self.source.port.addr.delete(self.source.ip_cidr)
        dev_mybridge.link.set_up()
        dev_mybridge.addr.add(self.source.ip_cidr)

    def _test_basic_port_filter_wrong_mac(self):
        # Setup filter with wrong IP/MAC address pair. Basic filters only allow
        # packets with specified address combinations, thus all packets will
        # be dropped.
        mac_ip_pair = dict(mac_addr="11:11:11:22:22:22", ip_addr=self.addr)
        filter_apply = FILTER_APPLY_TEMPLATE % mac_ip_pair
        ebtables_driver.ebtables_restore(filter_apply,
                                         self.source.execute)
        self.source.assert_no_ping(self.destination.ip)

        # Assure that ping will work once we unfilter the instance
        ebtables_driver.ebtables_restore(NO_FILTER_APPLY,
                                         self.source.execute)
        self.source.assert_ping(self.destination.ip)

    def _test_basic_port_filter_correct_mac(self):
        # Use the correct IP/MAC address pair for this one.
        mac_ip_pair = dict(mac_addr=self.mac, ip_addr=self.addr)

        filter_apply = FILTER_APPLY_TEMPLATE % mac_ip_pair
        ebtables_driver.ebtables_restore(filter_apply,
                                         self.source.execute)

        self.source.assert_ping(self.destination.ip)

    def test_ebtables_filtering(self):
        # Cannot parallelize those tests. Therefore need to call them
        # in order from a single function.
        self._test_basic_port_filter_wrong_mac()
        self._test_basic_port_filter_correct_mac()
