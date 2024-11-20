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
import netaddr
from neutron_lib import constants
from neutron_lib.plugins.ml2 import ovs_constants as ovs_consts
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.common import utils as common_utils
from neutron.tests.common import machine_fixtures
from neutron.tests.common import net_helpers

# NOTE: IPv6 uses NDP for obtaining destination endpoints link address that
# extends round-trip packet time in ICMP tests. The timeout value should be
# sufficient for correct scenarios but not too high because of negative
# tests.
ICMP_VERSION_TIMEOUTS = {
    constants.IP_VERSION_4: 1,
    constants.IP_VERSION_6: 2,
}


class ConnectionTesterException(Exception):
    pass


def _validate_direction(f):
    @functools.wraps(f)
    def wrap(self, direction, *args, **kwargs):
        if direction not in (constants.INGRESS_DIRECTION,
                             constants.EGRESS_DIRECTION):
            raise ConnectionTesterException('Unknown direction %s' % direction)
        return f(self, direction, *args, **kwargs)
    return wrap


def _get_packets_sent_received(src_namespace, dst_ip, count):
    pinger = net_helpers.Pinger(src_namespace, dst_ip, count=count)
    pinger.start()
    pinger.wait()
    return pinger.sent, pinger.received


def all_replied(src_ns, dst_ip, count):
    sent, received = _get_packets_sent_received(src_ns, dst_ip, count)
    return sent == received


def all_lost(src_ns, dst_ip, count):
    sent, received = _get_packets_sent_received(src_ns, dst_ip, count)
    return received == 0


class ConnectionTester(fixtures.Fixture):
    """Base class for testers

    This class implements API for various methods for testing connectivity. The
    concrete implementation relies on how encapsulated resources are
    configured. That means child classes should define resources by themselves
    (e.g. endpoints connected through linux bridge or ovs bridge).

    """

    UDP = net_helpers.NetcatTester.UDP
    TCP = net_helpers.NetcatTester.TCP
    ICMP = constants.PROTO_NAME_ICMP
    ARP = constants.ETHERTYPE_NAME_ARP
    INGRESS = constants.INGRESS_DIRECTION
    EGRESS = constants.EGRESS_DIRECTION

    def __init__(self, ip_cidr):
        self.ip_cidr = ip_cidr
        self.icmp_count = 3
        self.connectivity_timeout = 12

    def _setUp(self):
        self._protocol_to_method = {
            self.UDP: self._test_transport_connectivity,
            self.TCP: self._test_transport_connectivity,
            self.ICMP: self._test_icmp_connectivity,
            self.ARP: self._test_arp_connectivity}
        self._nc_testers = {}
        self._pingers = {}
        self.addCleanup(self.cleanup)

    def cleanup(self):
        for nc in self._nc_testers.values():
            nc.stop_processes()
        for pinger in self._pingers.values():
            pinger.stop()

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
    def peer_mac_address(self):
        return self._peer.port.link.address

    @peer_mac_address.setter
    def peer_mac_address(self, mac_address):
        self._peer.mac_address = mac_address

    @property
    def peer_namespace(self):
        return self._peer.namespace

    @property
    def peer_ip_address(self):
        return self._peer.ip

    def set_vm_default_gateway(self, default_gw):
        self._vm.set_default_gateway(default_gw)

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
            nc_tester.stop_processes()
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
        ip_version = common_utils.get_ip_version(ip_address)
        icmp_timeout = ICMP_VERSION_TIMEOUTS[ip_version]
        try:
            net_helpers.assert_ping(src_namespace, ip_address,
                                    timeout=icmp_timeout)
        except RuntimeError:
            raise ConnectionTesterException(
                "ICMP packets can't get from {} namespace to {} "
                "address".format(src_namespace, ip_address))

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
            dst_port_info = ''
            src_port_info = ''
            if dst_port is not None:
                dst_port_info = " and destination port %d" % dst_port
            if src_port is not None:
                src_port_info = " and source port %d" % src_port
            raise ConnectionTesterException("%s connection with protocol %s, "
                                            "source port %s, destination "
                                            "port %s was established but it "
                                            "shouldn't be possible" % (
                                                direction, protocol,
                                                src_port_info, dst_port_info))

    @_validate_direction
    def assert_established_connection(self, direction, protocol, src_port=None,
                                      dst_port=None):
        nc_params = (direction, protocol, src_port, dst_port)
        nc_tester = self._nc_testers.get(nc_params)
        if not nc_tester:
            raise ConnectionTesterException(
                "Attempting to test established %s connection with protocol %s"
                ", source port %s and destination port %s that hasn't been "
                "established yet by calling establish_connection()"
                % nc_params)
        if not nc_tester.is_established:
            nc_tester.stop_processes()
            raise ConnectionTesterException(
                '%s connection with protocol %s, source port %s and '
                'destination port %s is not established' % nc_params)
        try:
            nc_tester.test_connectivity()
        except RuntimeError:
            raise ConnectionTesterException(
                "Established %s connection with protocol %s, source port %s "
                "and destination port %s can no longer communicate")

    def assert_no_established_connection(self, direction, protocol,
                                         src_port=None, dst_port=None):
        try:
            self.assert_established_connection(direction, protocol, src_port,
                                               dst_port)
        except ConnectionTesterException:
            pass
        else:
            raise ConnectionTesterException(
                'Established %s connection with protocol %s, source port %s, '
                'destination port %s can still send packets through' % (
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

    def _get_pinger(self, direction):
        try:
            pinger = self._pingers[direction]
        except KeyError:
            src_namespace, dst_address = self._get_namespace_and_address(
                direction)
            pinger = net_helpers.Pinger(
                src_namespace, dst_address, interval=0.3)
            self._pingers[direction] = pinger
        return pinger

    def start_sending_icmp(self, direction):
        pinger = self._get_pinger(direction)
        pinger.start()

    def stop_sending_icmp(self, direction):
        pinger = self._get_pinger(direction)
        pinger.stop()

    def get_sent_icmp_packets(self, direction):
        pinger = self._get_pinger(direction)
        return pinger.sent

    def get_received_icmp_packets(self, direction):
        pinger = self._get_pinger(direction)
        return pinger.received

    def assert_net_unreachable(self, direction, destination):
        src_namespace, dst_address = self._get_namespace_and_address(
            direction)
        pinger = net_helpers.Pinger(src_namespace, destination, count=5)
        pinger.start()
        pinger.wait()
        if not pinger.destination_unreachable:
            raise ConnectionTesterException(
                'No Host Destination Unreachable packets were received when '
                'sending icmp packets to %s' % destination)

    def wait_for_connection(self, direction):
        src_ns, dst_ip = self._get_namespace_and_address(
            direction)
        all_replied_predicate = functools.partial(
            all_replied, src_ns, dst_ip, count=self.icmp_count)
        common_utils.wait_until_true(
            all_replied_predicate, timeout=self.connectivity_timeout,
            exception=ConnectionTesterException(
                "Not all ICMP packets replied from %s namespace to %s "
                "address." % self._get_namespace_and_address(direction)))

    def wait_for_no_connection(self, direction):
        src_ns, dst_ip = self._get_namespace_and_address(
            direction)
        all_lost_predicate = functools.partial(
            all_lost, src_ns, dst_ip, count=self.icmp_count)
        common_utils.wait_until_true(
            all_lost_predicate, timeout=self.connectivity_timeout,
            exception=ConnectionTesterException(
                "At least one packet got reply from %s namespace to %s "
                "address." % self._get_namespace_and_address(direction)))

    def set_peer_port_as_patch_port(self):
        pass

    def set_peer_port_as_vm_port(self):
        pass


class OVSBaseConnectionTester(ConnectionTester):

    @property
    def peer_port_id(self):
        return self._peer.port.id

    @property
    def vm_port_id(self):
        return self._vm.port.id

    @staticmethod
    def set_tag(port_name, bridge, tag):
        ovsdb = bridge.ovsdb
        with ovsdb.transaction() as txn:
            txn.add(ovsdb.db_set('Port', port_name, ('tag', tag)))
            txn.add(
                ovsdb.db_add(
                    'Port', port_name, 'other_config', {'tag': str(tag)}))


class OVSConnectionTester(OVSBaseConnectionTester):

    """Tester with OVS bridge in the middle

    The endpoints are created as OVS ports attached to the OVS bridge.

    NOTE: The OVS ports are connected from the namespace. This connection is
    currently not supported in OVS and may lead to unpredicted behavior:
    https://bugzilla.redhat.com/show_bug.cgi?id=1160340

    """

    def __init__(self, ip_cidr, br_int_cls):
        super().__init__(ip_cidr)
        self.br_int_cls = br_int_cls

    def _setUp(self):
        super()._setUp()
        br_name = self.useFixture(
            net_helpers.OVSBridgeFixture()).bridge.br_name
        self.bridge = self.br_int_cls(br_name)
        self.bridge.set_secure_mode()
        self.bridge.setup_controllers(cfg.CONF)
        self.bridge.setup_default_table()
        machines = self.useFixture(
            machine_fixtures.PeerMachines(
                self.bridge, self.ip_cidr)).machines
        self._peer = machines[0]
        self._vm = machines[1]
        self._set_port_attrs(self._peer.port)
        self._set_port_attrs(self._vm.port)

    def _set_port_attrs(self, port):
        port.id = uuidutils.generate_uuid()
        attrs = [('type', 'internal'),
                 ('external_ids', {
                     'iface-id': port.id,
                     'iface-status': 'active',
                     'attached-mac': port.link.address})]
        for column, value in attrs:
            self.bridge.set_db_attribute('Interface', port.name, column, value)

    def set_vm_tag(self, tag):
        self.set_tag(self._vm.port.name, self.bridge, tag)
        self._vm.port.vlan_tag = tag

    def set_peer_tag(self, tag):
        self.set_tag(self._peer.port.name, self.bridge, tag)
        self._peer.port.vlan_tag = tag

    def set_peer_port_as_patch_port(self):
        """As packets coming from tunneling bridges are always tagged with
        local VLAN tag, this flows will simulate the behavior.
        """
        self.bridge.add_flow(
            table=ovs_consts.LOCAL_SWITCHING,
            priority=110,
            vlan_tci=0,
            in_port=self.bridge.get_port_ofport(self._peer.port.name),
            actions='mod_vlan_vid:0x%x,'
                    'resubmit(,%d)' % (
                        self._peer.port.vlan_tag,
                        ovs_consts.LOCAL_SWITCHING)
        )
        self.bridge.add_flow(
            table=ovs_consts.TRANSIENT_TABLE,
            priority=4,
            dl_vlan='0x%x' % self._peer.port.vlan_tag,
            actions='strip_vlan,normal'
        )

    def set_peer_port_as_vm_port(self):
        """Remove flows simulating traffic from tunneling bridges.

        This method is opposite to set_peer_port_as_patch_port().
        """
        self.bridge.delete_flows(
            table=ovs_consts.LOCAL_SWITCHING,
            vlan_tci=0,
            in_port=self.bridge.get_port_ofport(self._peer.port.name),
        )
        self.bridge.delete_flows(
            table=ovs_consts.TRANSIENT_TABLE,
            dl_vlan='0x%x' % self._peer.port.vlan_tag,
        )


class OVSTrunkConnectionTester(OVSBaseConnectionTester):
    """Tester with OVS bridge and a trunk bridge

    Two endpoints: one is a VM that is connected to a port associated with a
    trunk (the port is created  on the trunk bridge), the other is a VM on the
    same network (the port is on the integration bridge).

    NOTE: The OVS ports are connected from the namespace. This connection is
    currently not supported in OVS and may lead to unpredicted behavior:
    https://bugzilla.redhat.com/show_bug.cgi?id=1160340

    """

    def __init__(self, ip_cidr, br_trunk_name):
        super().__init__(ip_cidr)
        self._br_trunk_name = br_trunk_name

    def _setUp(self):
        super()._setUp()
        self.bridge = self.useFixture(
            net_helpers.OVSBridgeFixture()).bridge
        self.br_trunk = self.useFixture(
            net_helpers.OVSTrunkBridgeFixture(self._br_trunk_name)).bridge
        self._peer = self.useFixture(machine_fixtures.FakeMachine(
                self.bridge, self.ip_cidr))
        ip_cidr = net_helpers.increment_ip_cidr(self.ip_cidr, 1)

        self._vm = self.useFixture(machine_fixtures.FakeMachine(
            self.br_trunk, ip_cidr))

    def add_vlan_interface_and_peer(self, vlan, ip_cidr):
        """Create a sub_port and a peer

        We create a sub_port that uses vlan as segmentation ID. In the vm
        namespace we create a vlan subinterface on the same vlan.
        A peer on the same network is created. When pinging from the peer
        to the sub_port packets will be tagged using the internal vlan ID
        of the network. The sub_port will remove that vlan tag and push the
        vlan specified in the segmentation ID. The packets will finally reach
        the vlan subinterface in the vm namespace.

        """

        network = netaddr.IPNetwork(ip_cidr)
        net_helpers.create_vlan_interface(
            self._vm.namespace, self._vm.port.name,
            self.vm_mac_address, network, vlan)
        self._ip_vlan = str(network.ip)
        ip_cidr = net_helpers.increment_ip_cidr(ip_cidr, 1)
        self._peer2 = self.useFixture(machine_fixtures.FakeMachine(
            self.bridge, ip_cidr))

    def set_vm_tag(self, tag):
        self.set_tag(self._vm.port.name, self.br_trunk, tag)

    def set_peer_tag(self, tag):
        self.set_tag(self._peer.port.name, self.bridge, tag)

    def _get_subport_namespace_and_address(self, direction):
        if direction == self.INGRESS:
            return self._peer2.namespace, self._ip_vlan
        return self._vm.namespace, self._peer2.ip

    def wait_for_sub_port_connectivity(self, direction):
        src_ns, dst_ip = self._get_subport_namespace_and_address(
            direction)
        all_replied_predicate = functools.partial(
            all_replied, src_ns, dst_ip, count=self.icmp_count)
        common_utils.wait_until_true(
            all_replied_predicate, timeout=self.connectivity_timeout,
            exception=ConnectionTesterException(
                "ICMP traffic from %s namespace to subport with address %s "
                "can't get through." % (src_ns, dst_ip)))

    def wait_for_sub_port_no_connectivity(self, direction):
        src_ns, dst_ip = self._get_subport_namespace_and_address(
            direction)
        all_lost_predicate = functools.partial(
            all_lost, src_ns, dst_ip, count=self.icmp_count)
        common_utils.wait_until_true(
            all_lost_predicate, timeout=self.connectivity_timeout,
            exception=ConnectionTesterException(
                "ICMP traffic from %s namespace to subport with address %s "
                "can still get through." % (src_ns, dst_ip)))


class LinuxBridgeConnectionTester(ConnectionTester):
    """Tester with linux bridge in the middle

    Both endpoints are placed in their separated namespace connected to
    bridge's namespace via veth pair.

    """

    def __init__(self, *args, **kwargs):
        self.bridge_name = kwargs.pop('bridge_name', None)
        super().__init__(*args, **kwargs)

    def _setUp(self):
        super()._setUp()
        bridge_args = {}
        if self.bridge_name:
            bridge_args = {'prefix': self.bridge_name,
                           'prefix_is_full_name': True}
        self.bridge = self.useFixture(
            net_helpers.LinuxBridgeFixture(**bridge_args)).bridge
        machines = self.useFixture(
            machine_fixtures.PeerMachines(
                self.bridge, self.ip_cidr)).machines
        self._peer = machines[0]
        self._vm = machines[1]

    @property
    def bridge_namespace(self):
        return self.bridge.namespace

    @property
    def vm_port_id(self):
        return net_helpers.VethFixture.get_peer_name(self._vm.port.name)

    @property
    def peer_port_id(self):
        return net_helpers.VethFixture.get_peer_name(self._peer.port.name)

    def flush_arp_tables(self):
        self.bridge.neigh.flush(4, 'all')
        super().flush_arp_tables()
