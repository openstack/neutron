# All Rights Reserved.
#
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
import functools

import fixtures

from neutron.agent import firewall
from neutron.tests.common import machine_fixtures
from neutron.tests.common import net_helpers


class ConnectionTesterException(Exception):
    pass


def _validate_direction(f):
    @functools.wraps(f)
    def wrap(self, direction, *args, **kwargs):
        if direction not in (firewall.INGRESS_DIRECTION,
                             firewall.EGRESS_DIRECTION):
            raise ConnectionTesterException('Unknown direction %s' % direction)
        return f(self, direction, *args, **kwargs)
    return wrap


class ConnectionTester(fixtures.Fixture):
    """Base class for testers

    This class implements API for various methods for testing connectivity. The
    concrete implementation relies on how encapsulated resources are
    configured. That means child classes should define resources by themselves
    (e.g. endpoints connected through linux bridge or ovs bridge).

    """

    UDP = net_helpers.NetcatTester.UDP
    TCP = net_helpers.NetcatTester.TCP
    ICMP = 'icmp'
    ARP = 'arp'
    INGRESS = firewall.INGRESS_DIRECTION
    EGRESS = firewall.EGRESS_DIRECTION

    def _setUp(self):
        self._protocol_to_method = {
            self.UDP: self._test_transport_connectivity,
            self.TCP: self._test_transport_connectivity,
            self.ICMP: self._test_icmp_connectivity,
            self.ARP: self._test_arp_connectivity}
        self._nc_testers = dict()
        self.addCleanup(self.cleanup)

    def cleanup(self):
        for nc in self._nc_testers.values():
            nc.stop_processes()

    @property
    def vm_namespace(self):
        return self._vm.namespace

    @property
    def vm_ip_address(self):
        return self._vm.ip

    @property
    def vm_ip_cidr(self):
        return self._vm.ip_cidr

    @vm_ip_cidr.setter
    def vm_ip_cidr(self, ip_cidr):
        self._vm.ip_cidr = ip_cidr

    @property
    def vm_mac_address(self):
        return self._vm.port.link.address

    @vm_mac_address.setter
    def vm_mac_address(self, mac_address):
        self._vm.mac_address = mac_address

    @property
    def peer_namespace(self):
        return self._peer.namespace

    @property
    def peer_ip_address(self):
        return self._peer.ip

    def flush_arp_tables(self):
        """Flush arptables in all used namespaces"""
        for machine in (self._peer, self._vm):
            machine.port.neigh.flush(4, 'all')

    def _test_transport_connectivity(self, direction, protocol, src_port,
                                     dst_port):
        nc_tester = self._create_nc_tester(direction, protocol, src_port,
                                           dst_port)
        try:
            nc_tester.test_connectivity()
        except RuntimeError as exc:
            raise ConnectionTesterException(
                "%s connection over %s protocol with %s source port and "
                "%s destination port can't be established: %s" % (
                    direction, protocol, src_port, dst_port, exc))

    @_validate_direction
    def _get_namespace_and_address(self, direction):
        if direction == self.INGRESS:
            return self.peer_namespace, self.vm_ip_address
        return self.vm_namespace, self.peer_ip_address

    def _test_icmp_connectivity(self, direction, protocol, src_port, dst_port):
        src_namespace, ip_address = self._get_namespace_and_address(direction)
        try:
            net_helpers.assert_ping(src_namespace, ip_address)
        except RuntimeError:
            raise ConnectionTesterException(
                "ICMP packets can't get from %s namespace to %s address" % (
                    src_namespace, ip_address))

    def _test_arp_connectivity(self, direction, protocol, src_port, dst_port):
        src_namespace, ip_address = self._get_namespace_and_address(direction)
        try:
            net_helpers.assert_arping(src_namespace, ip_address)
        except RuntimeError:
            raise ConnectionTesterException(
                "ARP queries to %s address have no response from %s namespace"
                % (ip_address, src_namespace))

    @_validate_direction
    def assert_connection(self, direction, protocol, src_port=None,
                          dst_port=None):
        testing_method = self._protocol_to_method[protocol]
        testing_method(direction, protocol, src_port, dst_port)

    def assert_no_connection(self, direction, protocol, src_port=None,
                             dst_port=None):
        try:
            self.assert_connection(direction, protocol, src_port, dst_port)
        except ConnectionTesterException:
            pass
        else:
            dst_port_info = str()
            src_port_info = str()
            if dst_port is not None:
                dst_port_info = " and destionation port %d" % dst_port
            if src_port is not None:
                src_port_info = " and source port %d" % src_port
            raise ConnectionTesterException("%s connection with %s protocol%s"
                                            "%s was established but it "
                                            "shouldn't be possible" % (
                                                direction, protocol,
                                                src_port_info, dst_port_info))

    @_validate_direction
    def assert_established_connection(self, direction, protocol, src_port=None,
                                      dst_port=None):
        nc_params = (direction, protocol, src_port, dst_port)
        nc_tester = self._nc_testers.get(nc_params)
        if nc_tester:
            if nc_tester.is_established:
                nc_tester.test_connectivity()
            else:
                raise ConnectionTesterException(
                    '%s connection with protocol %s, source port %s and '
                    'destination port %s is not established' % nc_params)
        else:
            raise ConnectionTesterException(
                "Attempting to test established %s connection with protocol %s"
                ", source port %s and destination port %s that hasn't been "
                "established yet by calling establish_connection()"
                % nc_params)

    def assert_no_established_connection(self, direction, protocol,
                                         src_port=None, dst_port=None):
        try:
            self.assert_established_connection(direction, protocol, src_port,
                                               dst_port)
        except ConnectionTesterException:
            pass
        else:
            raise ConnectionTesterException(
                'Established %s connection with protocol %s, source port  %s, '
                'destination port %s can still send packets throught' % (
                    direction, protocol, src_port, dst_port))

    @_validate_direction
    def establish_connection(self, direction, protocol, src_port=None,
                             dst_port=None):
        nc_tester = self._create_nc_tester(direction, protocol, src_port,
                                           dst_port)
        nc_tester.establish_connection()
        self.addCleanup(nc_tester.stop_processes)

    def _create_nc_tester(self, direction, protocol, src_port, dst_port):
        """Create netcat tester

        If there already exists a netcat tester that has established
        connection, exception is raised.
        """
        nc_key = (direction, protocol, src_port, dst_port)
        nc_tester = self._nc_testers.get(nc_key)
        if nc_tester and nc_tester.is_established:
            raise ConnectionTesterException(
                '%s connection using %s protocol, source port %s and '
                'destination port %s is already established' % (
                    direction, protocol, src_port, dst_port))

        if direction == self.INGRESS:
            client_ns = self.peer_namespace
            server_ns = self.vm_namespace
            server_addr = self.vm_ip_address
        else:
            client_ns = self.vm_namespace
            server_ns = self.peer_namespace
            server_addr = self.peer_ip_address

        server_port = dst_port or net_helpers.get_free_namespace_port(
            protocol, server_ns)
        nc_tester = net_helpers.NetcatTester(client_namespace=client_ns,
                                             server_namespace=server_ns,
                                             address=server_addr,
                                             protocol=protocol,
                                             src_port=src_port,
                                             dst_port=server_port)
        self._nc_testers[nc_key] = nc_tester
        return nc_tester


class LinuxBridgeConnectionTester(ConnectionTester):
    """Tester with linux bridge in the middle

    Both endpoints are placed in their separated namespace connected to
    bridge's namespace via veth pair.

    """

    def _setUp(self):
        super(LinuxBridgeConnectionTester, self)._setUp()
        self._bridge = self.useFixture(net_helpers.LinuxBridgeFixture()).bridge
        self._peer, self._vm = self.useFixture(
            machine_fixtures.PeerMachines(self._bridge)).machines

    @property
    def bridge_namespace(self):
        return self._bridge.namespace

    @property
    def vm_port_id(self):
        return net_helpers.VethFixture.get_peer_name(self._vm.port.name)

    def flush_arp_tables(self):
        self._bridge.neigh.flush(4, 'all')
        super(LinuxBridgeConnectionTester, self).flush_arp_tables()
