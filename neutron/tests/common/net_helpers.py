# Copyright (c) 2015 Thales Services SAS
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
#

import abc
from concurrent import futures
import contextlib
import functools
import os
import random
import re
import select
import shlex
import signal
import subprocess

import fixtures
import netaddr
from oslo_config import cfg
from oslo_utils import uuidutils
import six

from neutron.agent.common import config
from neutron.agent.common import ovs_lib
from neutron.agent.linux import bridge_lib
from neutron.agent.linux import interface
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.common import constants as n_const
from neutron.db import db_base_plugin_common
from neutron.plugins.ml2.drivers.linuxbridge.agent import \
    linuxbridge_neutron_agent as linuxbridge_agent
from neutron.tests import base as tests_base
from neutron.tests.common import base as common_base
from neutron.tests import tools

UNDEFINED = object()

NS_PREFIX = 'test-'
BR_PREFIX = 'test-br'
PORT_PREFIX = 'port'
VETH0_PREFIX = 'test-veth0'
VETH1_PREFIX = 'test-veth1'
PATCH_PREFIX = 'patch'
MACVTAP_PREFIX = 'macvtap'

# port name should be shorter than DEVICE_NAME_MAX_LEN because if this
# port is used to provide vlan connection between two linuxbridge
# agents then place for vlan ID is also required, Vlan ID can take max 4 digits
# and there is also additional "." in device name so it will in overall gives
# DEVICE_NAME_MAX_LEN = 15 chars
LB_DEVICE_NAME_MAX_LEN = 10

SS_SOURCE_PORT_PATTERN = re.compile(
    r'^.*\s+\d+\s+.*:(?P<port>\d+)\s+[0-9:].*')

READ_TIMEOUT = os.environ.get('OS_TEST_READ_TIMEOUT', 5)

CHILD_PROCESS_TIMEOUT = os.environ.get('OS_TEST_CHILD_PROCESS_TIMEOUT', 20)
CHILD_PROCESS_SLEEP = os.environ.get('OS_TEST_CHILD_PROCESS_SLEEP', 0.5)

TRANSPORT_PROTOCOLS = (n_const.PROTO_NAME_TCP, n_const.PROTO_NAME_UDP)


def increment_ip_cidr(ip_cidr, offset=1):
    """Increment ip_cidr offset times.

    example: increment_ip_cidr("1.2.3.4/24", 2) ==> "1.2.3.6/24"
    """
    net0 = netaddr.IPNetwork(ip_cidr)
    net = netaddr.IPNetwork(ip_cidr)
    net.value += offset
    if not net0.network < net.ip < net0[-1]:
        tools.fail(
            'Incorrect ip_cidr,offset tuple (%s,%s): "incremented" ip_cidr is '
            'outside ip_cidr' % (ip_cidr, offset))
    return str(net)


def set_namespace_gateway(port_dev, gateway_ip):
    """Set gateway for the namespace associated to the port."""
    if not port_dev.namespace:
        tools.fail('tests should not change test machine gateway')
    port_dev.route.add_gateway(gateway_ip)


def assert_ping(src_namespace, dst_ip, timeout=1, count=1):
    ipversion = netaddr.IPAddress(dst_ip).version
    ping_command = 'ping' if ipversion == 4 else 'ping6'
    ns_ip_wrapper = ip_lib.IPWrapper(src_namespace)
    ns_ip_wrapper.netns.execute([ping_command, '-c', count, '-W', timeout,
                                 dst_ip])


@contextlib.contextmanager
def async_ping(namespace, ips):
    with futures.ThreadPoolExecutor(max_workers=len(ips)) as executor:
        fs = [executor.submit(assert_ping, namespace, ip, count=10)
              for ip in ips]
        yield lambda: all(f.done() for f in fs)
        futures.wait(fs)
        for f in fs:
            f.result()


def assert_no_ping(src_namespace, dst_ip, timeout=1, count=1):
    try:
        assert_ping(src_namespace, dst_ip, timeout, count)
    except RuntimeError:
        pass
    else:
        tools.fail("destination ip %(destination)s is replying to ping from "
                   "namespace %(ns)s, but it shouldn't" %
                   {'ns': src_namespace, 'destination': dst_ip})


def assert_arping(src_namespace, dst_ip, source=None, timeout=1, count=1):
    """Send arp request using arping executable.

    NOTE: ARP protocol is used in IPv4 only. IPv6 uses Neighbour Discovery
    Protocol instead.
    """
    ns_ip_wrapper = ip_lib.IPWrapper(src_namespace)
    arping_cmd = ['arping', '-c', count, '-w', timeout]
    if source:
        arping_cmd.extend(['-s', source])
    arping_cmd.append(dst_ip)
    ns_ip_wrapper.netns.execute(arping_cmd)


def assert_no_arping(src_namespace, dst_ip, source=None, timeout=1, count=1):
    try:
        assert_arping(src_namespace, dst_ip, source, timeout, count)
    except RuntimeError:
        pass
    else:
        tools.fail("destination ip %(destination)s is replying to arp from "
                   "namespace %(ns)s, but it shouldn't" %
                   {'ns': src_namespace, 'destination': dst_ip})


def _get_source_ports_from_ss_output(output):
    ports = set()
    for line in output.splitlines():
        match = SS_SOURCE_PORT_PATTERN.match(line)
        if match:
            ports.add(match.group('port'))
    return ports


def get_unused_port(used, start=1024, end=65535):
    candidates = set(range(start, end + 1))
    return random.choice(list(candidates - used))


def get_free_namespace_port(protocol, namespace=None):
    """Return an unused port from given namespace

    WARNING: This function returns a port that is free at the execution time of
             this function. If this port is used later for binding then there
             is a potential danger that port will be no longer free. It's up to
             the programmer to handle error if port is already in use.

    :param protocol: Return free port for given protocol. Supported protocols
                     are 'tcp' and 'udp'.
    """
    if protocol == n_const.PROTO_NAME_TCP:
        param = '-tna'
    elif protocol == n_const.PROTO_NAME_UDP:
        param = '-una'
    else:
        raise ValueError("Unsupported procotol %s" % protocol)

    ip_wrapper = ip_lib.IPWrapper(namespace=namespace)
    output = ip_wrapper.netns.execute(['ss', param])
    used_ports = _get_source_ports_from_ss_output(output)

    return get_unused_port(used_ports)


def create_patch_ports(source, destination):
    """Hook up two OVS bridges.

    The result is two patch ports, each end connected to a bridge.
    The two patch port names will start with 'patch-', followed by identical
    four characters. For example patch-xyzw-fedora, and patch-xyzw-ubuntu,
    where fedora and ubuntu are random strings.

    :param source: Instance of OVSBridge
    :param destination: Instance of OVSBridge
    """
    common = tests_base.get_rand_name(max_length=4, prefix='')
    prefix = '%s-%s-' % (PATCH_PREFIX, common)

    source_name = tests_base.get_rand_device_name(prefix=prefix)
    destination_name = tests_base.get_rand_device_name(prefix=prefix)

    source.add_patch_port(source_name, destination_name)
    destination.add_patch_port(destination_name, source_name)


class RootHelperProcess(subprocess.Popen):
    def __init__(self, cmd, *args, **kwargs):
        for arg in ('stdin', 'stdout', 'stderr'):
            kwargs.setdefault(arg, subprocess.PIPE)
        self.namespace = kwargs.pop('namespace', None)
        self.cmd = cmd
        if self.namespace is not None:
            cmd = ['ip', 'netns', 'exec', self.namespace] + cmd
        root_helper = config.get_root_helper(utils.cfg.CONF)
        cmd = shlex.split(root_helper) + cmd
        self.child_pid = None
        super(RootHelperProcess, self).__init__(cmd, *args, **kwargs)
        self._wait_for_child_process()

    def kill(self, sig=signal.SIGKILL):
        pid = self.child_pid or str(self.pid)
        utils.execute(['kill', '-%d' % sig, pid], run_as_root=True)

    def read_stdout(self, timeout=None):
        return self._read_stream(self.stdout, timeout)

    @staticmethod
    def _read_stream(stream, timeout):
        if timeout:
            poller = select.poll()
            poller.register(stream.fileno())
            poll_predicate = functools.partial(poller.poll, 1)
            utils.wait_until_true(poll_predicate, timeout, 0.1,
                                  RuntimeError(
                                      'No output in %.2f seconds' % timeout))
        return stream.readline()

    def writeline(self, data):
        self.stdin.write(data + os.linesep)
        self.stdin.flush()

    def _wait_for_child_process(self, timeout=CHILD_PROCESS_TIMEOUT,
                                sleep=CHILD_PROCESS_SLEEP):
        def child_is_running():
            child_pid = utils.get_root_helper_child_pid(
                self.pid, run_as_root=True)
            if utils.pid_invoked_with_cmdline(child_pid, self.cmd):
                return True

        utils.wait_until_true(
            child_is_running,
            timeout,
            exception=RuntimeError("Process %s hasn't been spawned "
                                   "in %d seconds" % (self.cmd, timeout)))
        self.child_pid = utils.get_root_helper_child_pid(
            self.pid, run_as_root=True)

    @property
    def is_running(self):
        return self.poll() is None


class Pinger(object):
    """Class for sending ICMP packets asynchronously

    The aim is to keep sending ICMP packets on background while executing other
    code. After background 'ping' command is stopped, statistics are available.

    Difference to assert_(no_)ping() functions located in this module is that
    these methods send given count of ICMP packets while they wait for the
    exit code of 'ping' command.

    >>> pinger = Pinger('pinger_test', '192.168.0.2')

    >>> pinger.start(); time.sleep(5); pinger.stop()

    >>> pinger.sent, pinger.received
    7 7

    """

    stats_pattern = re.compile(
        r'^(?P<trans>\d+) packets transmitted,.*(?P<recv>\d+) received.*$')
    TIMEOUT = 15

    def __init__(self, namespace, address, count=None, timeout=1):
        self.proc = None
        self.namespace = namespace
        self.address = address
        self.count = count
        self.timeout = timeout
        self.sent = 0
        self.received = 0

    def _wait_for_death(self):
        is_dead = lambda: self.proc.poll() is not None
        utils.wait_until_true(
            is_dead, timeout=self.TIMEOUT, exception=RuntimeError(
                "Ping command hasn't ended after %d seconds." % self.TIMEOUT))

    def _parse_stats(self):
        for line in self.proc.stdout:
            result = self.stats_pattern.match(line)
            if result:
                self.sent = int(result.group('trans'))
                self.received = int(result.group('recv'))
                break
        else:
            raise RuntimeError("Didn't find ping statistics.")

    def start(self):
        if self.proc and self.proc.is_running:
            raise RuntimeError("This pinger has already a running process")
        ip_version = ip_lib.get_ip_version(self.address)
        ping_exec = 'ping' if ip_version == 4 else 'ping6'
        cmd = [ping_exec, self.address, '-W', str(self.timeout)]
        if self.count:
            cmd.extend(['-c', str(self.count)])
        self.proc = RootHelperProcess(cmd, namespace=self.namespace)

    def stop(self):
        if self.proc and self.proc.is_running:
            self.proc.kill(signal.SIGINT)
            self._wait_for_death()
            self._parse_stats()


class NetcatTester(object):
    TCP = n_const.PROTO_NAME_TCP
    UDP = n_const.PROTO_NAME_UDP
    VERSION_TO_ALL_ADDRESS = {
        4: '0.0.0.0',
        6: '::',
    }

    def __init__(self, client_namespace, server_namespace, address,
                 dst_port, protocol, server_address=None, src_port=None):

        """
        Tool for testing connectivity on transport layer using netcat
        executable.

        The processes are spawned lazily.

        :param client_namespace: Namespace in which netcat process that
                                 connects to other netcat will be spawned
        :param server_namespace: Namespace in which listening netcat process
                                 will be spawned
        :param address: Server address from client point of view
        :param dst_port: Port on which netcat listens
        :param protocol: Transport protocol, either 'tcp' or 'udp'
        :param server_address: Address in server namespace on which netcat
                               should listen
        :param src_port: Source port of netcat process spawned in client
                         namespace - packet will have src_port in TCP/UDP
                         header with this value

        """
        self.client_namespace = client_namespace
        self.server_namespace = server_namespace
        self._client_process = None
        self._server_process = None
        self.address = address
        self.dst_port = str(dst_port)
        self.src_port = str(src_port) if src_port else None
        if protocol not in TRANSPORT_PROTOCOLS:
            raise ValueError("Unsupported protocol %s" % protocol)
        self.protocol = protocol
        ip_version = netaddr.IPAddress(address).version
        self.server_address = (
            server_address or self.VERSION_TO_ALL_ADDRESS[ip_version])

    @property
    def client_process(self):
        if not self._client_process:
            self.establish_connection()
        return self._client_process

    @property
    def server_process(self):
        if not self._server_process:
            self._spawn_server_process()
        return self._server_process

    def _spawn_server_process(self):
        self._server_process = self._spawn_nc_in_namespace(
            self.server_namespace,
            address=self.server_address,
            listen=True)

    @property
    def is_established(self):
        return bool(self._client_process and not self._client_process.poll())

    def establish_connection(self):
        if self.is_established:
            raise RuntimeError('%(proto)s connection to %(ip_addr)s is already'
                               ' established' %
                               {'proto': self.protocol,
                                'ip_addr': self.address})

        if not self._server_process:
            self._spawn_server_process()
        self._client_process = self._spawn_nc_in_namespace(
            self.client_namespace,
            address=self.address)
        if self.protocol == self.UDP:
            # Create an ASSURED entry in conntrack table for UDP packets,
            # that requires 3-way communication
            # 1st transmission creates UNREPLIED
            # 2nd transmission removes UNREPLIED
            # 3rd transmission creates ASSURED
            data = 'foo'
            self.client_process.writeline(data)
            self.server_process.read_stdout(READ_TIMEOUT)
            self.server_process.writeline(data)
            self.client_process.read_stdout(READ_TIMEOUT)
            self.client_process.writeline(data)
            self.server_process.read_stdout(READ_TIMEOUT)

    def test_connectivity(self, respawn=False):
        testing_string = uuidutils.generate_uuid()
        if respawn:
            self.stop_processes()

        self.client_process.writeline(testing_string)
        message = self.server_process.read_stdout(READ_TIMEOUT).strip()
        self.server_process.writeline(message)
        message = self.client_process.read_stdout(READ_TIMEOUT).strip()

        return message == testing_string

    def _spawn_nc_in_namespace(self, namespace, address, listen=False):
        cmd = ['nc', address, self.dst_port]
        if self.protocol == self.UDP:
            cmd.append('-u')
        if listen:
            cmd.append('-l')
            if self.protocol == self.TCP:
                cmd.append('-k')
        else:
            cmd.extend(['-w', '20'])
            if self.src_port:
                cmd.extend(['-p', self.src_port])
        proc = RootHelperProcess(cmd, namespace=namespace)
        return proc

    def stop_processes(self):
        for proc_attr in ('_client_process', '_server_process'):
            proc = getattr(self, proc_attr)
            if proc:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
                setattr(self, proc_attr, None)


class NamespaceFixture(fixtures.Fixture):
    """Create a namespace.

    :ivar ip_wrapper: created namespace
    :type ip_wrapper: IPWrapper
    :ivar name: created namespace name
    :type name: str
    """

    def __init__(self, prefix=NS_PREFIX):
        super(NamespaceFixture, self).__init__()
        self.prefix = prefix

    def _setUp(self):
        ip = ip_lib.IPWrapper()
        self.name = self.prefix + uuidutils.generate_uuid()
        self.addCleanup(self.destroy)
        self.ip_wrapper = ip.ensure_namespace(self.name)

    def destroy(self):
        if self.ip_wrapper.netns.exists(self.name):
            self.ip_wrapper.netns.delete(self.name)


class VethFixture(fixtures.Fixture):
    """Create a veth.

    :ivar ports: created veth ports
    :type ports: tuple of 2 IPDevice
    """

    def _setUp(self):
        ip_wrapper = ip_lib.IPWrapper()

        self.ports = common_base.create_resource(
            VETH0_PREFIX,
            lambda name: ip_wrapper.add_veth(name, self.get_peer_name(name)))

        self.addCleanup(self.destroy)

    def destroy(self):
        for port in self.ports:
            ip_wrapper = ip_lib.IPWrapper(port.namespace)
            if (ip_wrapper.netns.exists(port.namespace) or
                port.namespace is None):
                try:
                    ip_wrapper.del_veth(port.name)
                    break
                except RuntimeError:
                    # NOTE(cbrandily): It seems a veth is automagically deleted
                    # when a namespace owning a veth endpoint is deleted.
                    pass

    @staticmethod
    def get_peer_name(name):
        if name.startswith(VETH0_PREFIX):
            return name.replace(VETH0_PREFIX, VETH1_PREFIX)
        elif name.startswith(VETH1_PREFIX):
            return name.replace(VETH1_PREFIX, VETH0_PREFIX)
        else:
            tools.fail('%s is not a valid VethFixture veth endpoint' % name)


class NamedVethFixture(VethFixture):
    """Create a veth with at least one specified name of a device

    :ivar ports: created veth ports
    :type ports: tuple of 2 IPDevice
    """

    def __init__(self, veth0_prefix=VETH0_PREFIX, veth1_prefix=VETH1_PREFIX):
        super(NamedVethFixture, self).__init__()
        self.veth0_name = self.get_veth_name(veth0_prefix)
        self.veth1_name = self.get_veth_name(veth1_prefix)

    def _setUp(self):
        ip_wrapper = ip_lib.IPWrapper()
        self.ports = ip_wrapper.add_veth(self.veth0_name, self.veth1_name)
        self.addCleanup(self.destroy)

    @staticmethod
    def get_veth_name(name):
        if name.startswith(VETH0_PREFIX):
            return tests_base.get_rand_device_name(VETH0_PREFIX)
        if name.startswith(VETH1_PREFIX):
            return tests_base.get_rand_device_name(VETH1_PREFIX)
        return name


class MacvtapFixture(fixtures.Fixture):
    """Create a macvtap.

    :param src_dev: source device for macvtap
    :type src_dev: IPDevice
    :param mode: mode of macvtap
    :type mode: string
    :ivar ip_dev: created macvtap
    :type ip_dev: IPDevice
    """
    def __init__(self, src_dev=None, mode=None, prefix=MACVTAP_PREFIX):
        super(MacvtapFixture, self).__init__()
        self.src_dev = src_dev
        self.mode = mode
        self.prefix = prefix

    def _setUp(self):
        ip_wrapper = ip_lib.IPWrapper()
        self.ip_dev = common_base.create_resource(
            self.prefix,
            ip_wrapper.add_macvtap,
            self.src_dev, mode=self.mode)
        self.addCleanup(self.destroy)

    def destroy(self):
        ip_wrapper = ip_lib.IPWrapper(self.ip_dev.namespace)
        if (ip_wrapper.netns.exists(self.ip_dev.namespace) or
            self.ip_dev.namespace is None):
            try:
                self.ip_dev.link.delete()
            except RuntimeError:
                pass


@six.add_metaclass(abc.ABCMeta)
class PortFixture(fixtures.Fixture):
    """Create a port.

    :ivar port: created port
    :type port: IPDevice
    :ivar bridge: port bridge
    """

    def __init__(self, bridge=None, namespace=None, mac=None, port_id=None):
        super(PortFixture, self).__init__()
        self.bridge = bridge
        self.namespace = namespace
        self.mac = (
            mac or db_base_plugin_common.DbBasePluginCommon._generate_mac())
        self.port_id = port_id or uuidutils.generate_uuid()

    @abc.abstractmethod
    def _create_bridge_fixture(self):
        pass

    @abc.abstractmethod
    def _setUp(self):
        super(PortFixture, self)._setUp()
        if not self.bridge:
            self.bridge = self.useFixture(self._create_bridge_fixture()).bridge

    @classmethod
    def get(cls, bridge, namespace=None, mac=None, port_id=None):
        """Deduce PortFixture class from bridge type and instantiate it."""
        if isinstance(bridge, ovs_lib.OVSBridge):
            return OVSPortFixture(bridge, namespace, mac, port_id)
        if isinstance(bridge, bridge_lib.BridgeDevice):
            return LinuxBridgePortFixture(bridge, namespace, mac, port_id)
        if isinstance(bridge, VethBridge):
            return VethPortFixture(bridge, namespace)
        tools.fail('Unexpected bridge type: %s' % type(bridge))


class OVSBridgeFixture(fixtures.Fixture):
    """Create an OVS bridge.

    :ivar prefix: bridge name prefix
    :type prefix: str
    :ivar bridge: created bridge
    :type bridge: OVSBridge
    """

    def __init__(self, prefix=BR_PREFIX):
        super(OVSBridgeFixture, self).__init__()
        self.prefix = prefix

    def _setUp(self):
        ovs = ovs_lib.BaseOVS()
        self.bridge = common_base.create_resource(self.prefix, ovs.add_bridge)
        self.addCleanup(self.bridge.destroy)


class OVSPortFixture(PortFixture):

    def _create_bridge_fixture(self):
        return OVSBridgeFixture()

    def _setUp(self):
        super(OVSPortFixture, self)._setUp()

        interface_config = cfg.ConfigOpts()
        interface_config.register_opts(interface.OPTS)
        ovs_interface = interface.OVSInterfaceDriver(interface_config)

        # because in some tests this port can be used to providing connection
        # between linuxbridge agents and vlan_id can be also added to this
        # device name it has to be max LB_DEVICE_NAME_MAX_LEN long
        port_name = tests_base.get_rand_name(
            LB_DEVICE_NAME_MAX_LEN,
            PORT_PREFIX
        )
        ovs_interface.plug_new(
            None,
            self.port_id,
            port_name,
            self.mac,
            bridge=self.bridge.br_name,
            namespace=self.namespace)
        self.addCleanup(self.bridge.delete_port, port_name)
        self.port = ip_lib.IPDevice(port_name, self.namespace)


class LinuxBridgeFixture(fixtures.Fixture):
    """Create a linux bridge.

    :ivar bridge: created bridge
    :type bridge: BridgeDevice
    :ivar namespace: created bridge namespace
    :type namespace: str
    """
    def __init__(self, prefix=BR_PREFIX, namespace=UNDEFINED,
                 prefix_is_full_name=False):
        super(LinuxBridgeFixture, self).__init__()
        self.prefix = prefix
        self.prefix_is_full_name = prefix_is_full_name
        self.namespace = namespace

    def _setUp(self):
        if self.namespace is UNDEFINED:
            self.namespace = self.useFixture(NamespaceFixture()).name
        self.bridge = self._create_bridge()
        self.addCleanup(self.safe_delete)
        self.bridge.link.set_up()
        self.addCleanup(self.safe_set_down)

    def safe_set_down(self):
        try:
            self.bridge.link.set_down()
        except RuntimeError:
            pass

    def safe_delete(self):
        try:
            self.bridge.delbr()
        except RuntimeError:
            pass

    def _create_bridge(self):
        if self.prefix_is_full_name:
            return bridge_lib.BridgeDevice.addbr(
                name=self.prefix,
                namespace=self.namespace
            )
        else:
            return common_base.create_resource(
                self.prefix,
                bridge_lib.BridgeDevice.addbr,
                namespace=self.namespace)


class LinuxBridgePortFixture(PortFixture):
    """Create a linux bridge port.

    :ivar port: created port
    :type port: IPDevice
    :ivar br_port: bridge side veth peer port
    :type br_port: IPDevice
    """

    def __init__(self, bridge, namespace=None, mac=None, port_id=None):
        super(LinuxBridgePortFixture, self).__init__(
            bridge, namespace, mac, port_id)
        # we need to override port_id value here because in Port() class it is
        # always generated as random. In LinuxBridgePortFixture we need to have
        # it empty if it was not give because then proper veth_pair will be
        # created (for example in some functional tests)
        self.port_id = port_id

    def _create_bridge_fixture(self):
        return LinuxBridgeFixture()

    def _setUp(self):
        super(LinuxBridgePortFixture, self)._setUp()
        br_port_name = self._get_port_name()
        if br_port_name:
            self.br_port, self.port = self.useFixture(
                NamedVethFixture(veth0_prefix=br_port_name)).ports
        else:
            self.br_port, self.port = self.useFixture(VethFixture()).ports

        if self.mac:
            self.port.link.set_address(self.mac)

        # bridge side
        br_ip_wrapper = ip_lib.IPWrapper(self.bridge.namespace)
        br_ip_wrapper.add_device_to_namespace(self.br_port)
        self.bridge.addif(self.br_port)
        self.br_port.link.set_up()

        # port side
        ns_ip_wrapper = ip_lib.IPWrapper(self.namespace)
        ns_ip_wrapper.add_device_to_namespace(self.port)
        self.port.link.set_up()

    def _get_port_name(self):
        if self.port_id:
            return linuxbridge_agent.LinuxBridgeManager.get_tap_device_name(
                self.port_id)
        return None


class VethBridge(object):

    def __init__(self, ports):
        self.ports = ports
        self.unallocated_ports = set(self.ports)

    def allocate_port(self):
        try:
            return self.unallocated_ports.pop()
        except KeyError:
            tools.fail('All FakeBridge ports (%s) are already allocated.' %
                       len(self.ports))


class VethBridgeFixture(fixtures.Fixture):
    """Simulate a bridge with a veth.

    :ivar bridge: created bridge
    :type bridge: FakeBridge
    """

    def _setUp(self):
        ports = self.useFixture(VethFixture()).ports
        self.bridge = VethBridge(ports)


class VethPortFixture(PortFixture):
    """Create a veth bridge port.

    :ivar port: created port
    :type port: IPDevice
    """

    def _create_bridge_fixture(self):
        return VethBridgeFixture()

    def _setUp(self):
        super(VethPortFixture, self)._setUp()
        self.port = self.bridge.allocate_port()

        ns_ip_wrapper = ip_lib.IPWrapper(self.namespace)
        ns_ip_wrapper.add_device_to_namespace(self.port)
        self.port.link.set_up()
