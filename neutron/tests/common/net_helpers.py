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
from oslo_utils import uuidutils
import six

from neutron.agent.common import config
from neutron.agent.common import ovs_lib
from neutron.agent.linux import bridge_lib
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.common import constants as n_const
from neutron.tests import base as tests_base
from neutron.tests.common import base as common_base
from neutron.tests import tools

NS_PREFIX = 'test-'
BR_PREFIX = 'test-br'
PORT_PREFIX = 'test-port'
VETH0_PREFIX = 'test-veth0'
VETH1_PREFIX = 'test-veth1'

SS_SOURCE_PORT_PATTERN = re.compile(
    r'^.*\s+\d+\s+.*:(?P<port>\d+)\s+[0-9:].*')

READ_TIMEOUT = os.environ.get('OS_TEST_READ_TIMEOUT', 5)

CHILD_PROCESS_TIMEOUT = os.environ.get('OS_TEST_CHILD_PROCESS_TIMEOUT', 20)
CHILD_PROCESS_SLEEP = os.environ.get('OS_TEST_CHILD_PROCESS_SLEEP', 0.5)

TRANSPORT_PROTOCOLS = (n_const.PROTO_NAME_TCP, n_const.PROTO_NAME_UDP)


def get_rand_port_name():
    return tests_base.get_rand_name(max_length=n_const.DEVICE_NAME_MAX_LEN,
                                    prefix=PORT_PREFIX)


def increment_ip_cidr(ip_cidr, offset=1):
    """Increment ip_cidr offset times.

    example: increment_ip_cidr("1.2.3.4/24", 2) ==> "1.2.3.6/24"
    """
    net0 = netaddr.IPNetwork(ip_cidr)
    net = netaddr.IPNetwork(ip_cidr)
    net.value += offset
    if not net0.network < net.ip < net0.broadcast:
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


class NetcatTester(object):
    TESTING_STRING = 'foo'
    TCP = n_const.PROTO_NAME_TCP
    UDP = n_const.PROTO_NAME_UDP

    def __init__(self, client_namespace, server_namespace, address,
                 dst_port, protocol, server_address='0.0.0.0', src_port=None):
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
        self.server_address = server_address
        self.dst_port = str(dst_port)
        self.src_port = str(src_port) if src_port else None
        if protocol not in TRANSPORT_PROTOCOLS:
            raise ValueError("Unsupported protocol %s" % protocol)
        self.protocol = protocol

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
        if self._client_process:
            raise RuntimeError('%(proto)s connection to $(ip_addr)s is already'
                               ' established' %
                               {'proto': self.protocol,
                                'ip_addr': self.address})

        if not self._server_process:
            self._spawn_server_process()
        self._client_process = self._spawn_nc_in_namespace(
            self.client_namespace,
            address=self.address)
        if self.protocol == self.UDP:
            # Create an entry in conntrack table for UDP packets
            self.client_process.writeline(self.TESTING_STRING)

    def test_connectivity(self, respawn=False):
        stop_required = (respawn and self._client_process and
                         self._client_process.poll() is not None)
        if stop_required:
            self.stop_processes()

        self.client_process.writeline(self.TESTING_STRING)
        message = self.server_process.read_stdout(READ_TIMEOUT).strip()
        self.server_process.writeline(message)
        message = self.client_process.read_stdout(READ_TIMEOUT).strip()

        return message == self.TESTING_STRING

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
    :type ports: IPDevice 2-uplet
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


@six.add_metaclass(abc.ABCMeta)
class PortFixture(fixtures.Fixture):
    """Create a port.

    :ivar port: created port
    :type port: IPDevice
    :ivar bridge: port bridge
    """

    def __init__(self, bridge=None, namespace=None):
        super(PortFixture, self).__init__()
        self.bridge = bridge
        self.namespace = namespace

    @abc.abstractmethod
    def _create_bridge_fixture(self):
        pass

    @abc.abstractmethod
    def _setUp(self):
        super(PortFixture, self)._setUp()
        if not self.bridge:
            self.bridge = self.useFixture(self._create_bridge_fixture()).bridge

    @classmethod
    def get(cls, bridge, namespace=None):
        """Deduce PortFixture class from bridge type and instantiate it."""
        if isinstance(bridge, ovs_lib.OVSBridge):
            return OVSPortFixture(bridge, namespace)
        if isinstance(bridge, bridge_lib.BridgeDevice):
            return LinuxBridgePortFixture(bridge, namespace)
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

    def __init__(self, bridge=None, namespace=None, attrs=None):
        super(OVSPortFixture, self).__init__(bridge, namespace)
        if attrs is None:
            attrs = []
        self.attrs = attrs

    def _create_bridge_fixture(self):
        return OVSBridgeFixture()

    def _setUp(self):
        super(OVSPortFixture, self)._setUp()

        port_name = common_base.create_resource(PORT_PREFIX, self.create_port)
        self.addCleanup(self.bridge.delete_port, port_name)
        self.port = ip_lib.IPDevice(port_name)

        ns_ip_wrapper = ip_lib.IPWrapper(self.namespace)
        ns_ip_wrapper.add_device_to_namespace(self.port)
        self.port.link.set_up()

    def create_port(self, name):
        self.attrs.insert(0, ('type', 'internal'))
        self.bridge.add_port(name, *self.attrs)
        return name


class LinuxBridgeFixture(fixtures.Fixture):
    """Create a linux bridge.

    :ivar bridge: created bridge
    :type bridge: BridgeDevice
    :ivar namespace: created bridge namespace
    :type namespace: str
    """

    def _setUp(self):
        self.namespace = self.useFixture(NamespaceFixture()).name
        self.bridge = common_base.create_resource(
            BR_PREFIX,
            bridge_lib.BridgeDevice.addbr,
            namespace=self.namespace)
        self.addCleanup(self.bridge.delbr)
        self.bridge.link.set_up()
        self.addCleanup(self.bridge.link.set_down)


class LinuxBridgePortFixture(PortFixture):
    """Create a linux bridge port.

    :ivar port: created port
    :type port: IPDevice
    :ivar br_port: bridge side veth peer port
    :type br_port: IPDevice
    """

    def _create_bridge_fixture(self):
        return LinuxBridgeFixture()

    def _setUp(self):
        super(LinuxBridgePortFixture, self)._setUp()
        self.port, self.br_port = self.useFixture(VethFixture()).ports

        # bridge side
        br_ip_wrapper = ip_lib.IPWrapper(self.bridge.namespace)
        br_ip_wrapper.add_device_to_namespace(self.br_port)
        self.bridge.addif(self.br_port)
        self.br_port.link.set_up()

        # port side
        ns_ip_wrapper = ip_lib.IPWrapper(self.namespace)
        ns_ip_wrapper.add_device_to_namespace(self.port)
        self.port.link.set_up()


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
