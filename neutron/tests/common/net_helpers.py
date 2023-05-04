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
import os
import random
import re
import select
import shlex
import signal
import subprocess
import time
from unittest import mock

import fixtures
import netaddr
from neutron_lib import constants as n_const
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import uuidutils

from neutron.agent.common import ovs_lib
from neutron.agent.linux import bridge_lib
from neutron.agent.linux import interface
from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_firewall
from neutron.agent.linux import utils
from neutron.common import utils as common_utils
from neutron.conf.agent import common as config
from neutron.db import db_base_plugin_common as db_base
from neutron.plugins.ml2.drivers.linuxbridge.agent import \
    linuxbridge_neutron_agent as linuxbridge_agent
from neutron.services.trunk.drivers.openvswitch.agent import trunk_manager
from neutron.tests.common import base as common_base
from neutron.tests.common import helpers
from neutron.tests import tools

LOG = logging.getLogger(__name__)

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
    r'^.*\s+\d+\s+.*:(?P<port>\d+)\s+[^\s]+:.*')

READ_TIMEOUT = int(
    os.environ.get('OS_TEST_READ_TIMEOUT', 5))

CHILD_PROCESS_TIMEOUT = int(
    os.environ.get('OS_TEST_CHILD_PROCESS_TIMEOUT', 20))
CHILD_PROCESS_SLEEP = float(
    os.environ.get('OS_TEST_CHILD_PROCESS_SLEEP', 0.5))

TRANSPORT_PROTOCOLS = (n_const.PROTO_NAME_TCP, n_const.PROTO_NAME_UDP,
                       n_const.PROTO_NAME_SCTP)

OVS_MANAGER_TEST_PORT_FIRST = 6610
OVS_MANAGER_TEST_PORT_LAST = 6639


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


def assert_ping(src_namespace, dst_ip, timeout=1, count=3, retry_count=1):
    ipversion = netaddr.IPAddress(dst_ip).version
    ping_command = 'ping' if ipversion == 4 else 'ping6'
    ns_ip_wrapper = ip_lib.IPWrapper(src_namespace)
    while retry_count:
        retry_count -= 1
        try:
            ns_ip_wrapper.netns.execute(
                [ping_command, '-W', timeout, '-c', count, dst_ip],
                privsep_exec=True)
            return
        except n_exc.ProcessExecutionError as exc:
            if not retry_count:
                raise exc


def assert_async_ping(src_namespace, dst_ip, timeout=1, count=1, interval=1):
    ipversion = netaddr.IPAddress(dst_ip).version
    ping_command = 'ping' if ipversion == 4 else 'ping6'
    ns_ip_wrapper = ip_lib.IPWrapper(src_namespace)

    # See bug 1588731 for explanation why using -c count ping option
    # cannot be used and it needs to be done using the following workaround.
    for _index in range(count):
        start_time = time.time()
        ns_ip_wrapper.netns.execute(
            [ping_command, '-W', timeout, '-c', '1', dst_ip],
            privsep_exec=True)
        end_time = time.time()
        diff = end_time - start_time
        if 0 < diff < interval:
            # wait at most "interval" seconds between individual pings
            time.sleep(interval - diff)


@contextlib.contextmanager
def async_ping(namespace, ips, timeout=1, count=10):
    with futures.ThreadPoolExecutor(max_workers=len(ips)) as executor:
        fs = [executor.submit(assert_async_ping, namespace, ip, count=count,
                              timeout=timeout)
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
    ns_ip_wrapper.netns.execute(arping_cmd, privsep_exec=True)


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
            ports.add(int(match.group('port')))
    return ports


def get_unused_port(used, start=1024, end=None):
    if end is None:
        port_range = utils.execute(
            ['sysctl', '-n', 'net.ipv4.ip_local_port_range'], run_as_root=True,
            privsep_exec=True)
        end = int(port_range.split()[0]) - 1

    candidates = set(range(start, end + 1))
    return random.choice(list(candidates - used))


def get_free_namespace_port(protocol, namespace=None, start=1024, end=None):
    """Return an unused port from given namespace

    WARNING: This function returns a port that is free at the execution time of
             this function. If this port is used later for binding then there
             is a potential danger that port will be no longer free. It's up to
             the programmer to handle error if port is already in use.

    :param protocol: Return free port for given protocol. Supported protocols
                     are 'tcp' and 'udp'.
    :param namespace: Namespace in which free port has to be returned.
    :param start: The starting port number.
    :param end: The ending port number (free port that is returned would be
                between (start, end) values.
    """
    if protocol == n_const.PROTO_NAME_TCP:
        param = '-tna'
    elif protocol == n_const.PROTO_NAME_UDP:
        param = '-una'
    else:
        raise ValueError("Unsupported protocol %s" % protocol)

    ip_wrapper = ip_lib.IPWrapper(namespace=namespace)
    output = ip_wrapper.netns.execute(['ss', param], run_as_root=True,
                                      privsep_exec=True)
    used_ports = _get_source_ports_from_ss_output(output)

    return get_unused_port(used_ports, start, end)


def set_local_port_range(start, end):
    utils.execute(
        ['sysctl', '-w', 'net.ipv4.ip_local_port_range=%d %d' % (start, end)],
        run_as_root=True, privsep_exec=True)
    utils.execute(['sysctl', '-p'], run_as_root=True, privsep_exec=True)
    # verify
    port_range = utils.execute(
        ['sysctl', '-n', 'net.ipv4.ip_local_port_range'], run_as_root=True,
        privsep_exec=True)
    assert int(port_range.split()[0]) == start
    assert int(port_range.split()[1]) == end


def create_patch_ports(source, destination):
    """Hook up two OVS bridges.

    The result is two patch ports, each end connected to a bridge.
    The two patch port names will start with 'patch-', followed by identical
    four characters. For example patch-xyzw-fedora, and patch-xyzw-ubuntu,
    where fedora and ubuntu are random strings.

    :param source: Instance of OVSBridge
    :param destination: Instance of OVSBridge
    """
    common = common_utils.get_rand_name(max_length=4, prefix='')
    prefix = '%s-%s-' % (PATCH_PREFIX, common)

    source_name = common_utils.get_rand_device_name(prefix=prefix)
    destination_name = common_utils.get_rand_device_name(prefix=prefix)

    source.add_patch_port(source_name, destination_name)
    destination.add_patch_port(destination_name, source_name)


def create_vlan_interface(
        namespace, port_name, mac_address, ip_address, vlan_tag):
    """Create a VLAN interface in namespace with IP address.

    :param namespace: Namespace in which VLAN interface should be created.
    :param port_name: Name of the port to which VLAN should be added.
    :param ip_address: IPNetwork instance containing the VLAN interface IP
                       address.
    :param vlan_tag: VLAN tag for VLAN interface.
    """
    ip_wrap = ip_lib.IPWrapper(namespace)
    dev_name = "%s.%d" % (port_name, vlan_tag)
    ip_wrap.add_vlan(dev_name, port_name, vlan_tag)
    dev = ip_wrap.device(dev_name)
    dev.addr.add(str(ip_address))
    dev.link.set_address(mac_address)
    dev.link.set_up()

    return dev


class RootHelperProcess(subprocess.Popen):
    def __init__(self, cmd, *args, **kwargs):
        for arg in ('stdin', 'stdout', 'stderr'):
            kwargs.setdefault(arg, subprocess.PIPE)
        kwargs.setdefault('universal_newlines', True)

        self.namespace = kwargs.pop('namespace', None)
        self.cmd = cmd
        if self.namespace is not None:
            cmd = ['ip', 'netns', 'exec', self.namespace] + cmd
        root_helper = config.get_root_helper(utils.cfg.CONF)
        cmd = shlex.split(root_helper) + cmd
        self.child_pid = None
        LOG.debug("Spawning process %s", cmd)
        super(RootHelperProcess, self).__init__(cmd, *args, **kwargs)
        self._wait_for_child_process()

    def kill(self, sig=signal.SIGKILL, skip_errors=None):
        skip_errors = (
            ["No such process"] if skip_errors is None else skip_errors)
        pid = self.child_pid or str(self.pid)
        try:
            utils.execute(['kill', '-%d' % sig, pid], run_as_root=True)
        except n_exc.ProcessExecutionError as e:
            # NOTE(slaweq): kill command returns 1 for many
            # different issues, e.g. when there is no such process to kill
            # (which we want to handle here) but also in cases like e.g. when
            # user don't have privileges to kill process (which we don't want
            # to silently hide). Sometimes we don't want really to fail if e.g.
            # we are trying to kill process which already don't exists, so we
            # can check if that was the error and not fail than.
            for skip_error in skip_errors:
                if skip_error in str(e):
                    LOG.debug('Kill process %(pid)s failed due to error: '
                              '%(err)s. This error can be ignored.',
                              {'pid': pid, 'err': e})
                    return
            raise e

    def read_stdout(self, timeout=None):
        return self._read_stream(self.stdout, timeout)

    @staticmethod
    def _read_stream(stream, timeout):
        if timeout:
            rready, _wready, _xready = select.select([stream], [], [], timeout)
            if not rready:
                raise RuntimeError('No output in %.2f seconds' % timeout)
        return stream.readline()

    def writeline(self, data):
        self.stdin.write(data + os.linesep)
        self.stdin.flush()

    def _wait_for_child_process(self, timeout=CHILD_PROCESS_TIMEOUT,
                                sleep=CHILD_PROCESS_SLEEP):
        def child_is_running():
            child_pid = utils.get_root_helper_child_pid(
                self.pid, self.cmd, run_as_root=True)
            if utils.pid_invoked_with_cmdline(child_pid, self.cmd):
                return True

        try:
            common_utils.wait_until_true(child_is_running, timeout)
        except common_utils.WaitTimeout:
            # If there is an error, the stderr and stdout pipes usually have
            # information returned by the command executed. If not, timeout
            # the pipe communication quickly.
            stdout = stderr = ''
            try:
                stdout, stderr = self.communicate(timeout=0.5)
            except subprocess.TimeoutExpired:
                pass
            msg = ("Process %(cmd)s hasn't been spawned in %(seconds)d "
                   "seconds. Return code: %(ret_code)s, stdout: %(stdout)s, "
                   "stderr: %(stderr)s" %
                   {'cmd': self.cmd, 'seconds': timeout,
                    'ret_code': self.returncode, 'stdout': stdout,
                    'stderr': stderr})
            raise RuntimeError(msg)

        self.child_pid = utils.get_root_helper_child_pid(
            self.pid, self.cmd, run_as_root=True)

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
    unreachable_pattern = re.compile(
        r'.* Destination .* Unreachable')
    TIMEOUT = 15

    def __init__(self, namespace, address, count=None, timeout=1,
                 interval=None):
        self.proc = None
        self.namespace = namespace
        self.address = address
        self.count = count
        self.timeout = timeout
        self.destination_unreachable = False
        self.sent = 0
        self.received = 0
        self.interval = interval

    def _wait_for_death(self):
        is_dead = lambda: self.proc.poll() is not None
        common_utils.wait_until_true(
            is_dead, timeout=self.TIMEOUT, exception=RuntimeError(
                "Ping command hasn't ended after %d seconds." % self.TIMEOUT))

    def _parse_stats(self):
        for line in self.proc.stdout:
            if (not self.destination_unreachable and
                    self.unreachable_pattern.match(line)):
                self.destination_unreachable = True
                continue
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
        ip_version = common_utils.get_ip_version(self.address)
        ping_exec = 'ping' if ip_version == n_const.IP_VERSION_4 else 'ping6'
        cmd = [ping_exec, '-W', str(self.timeout)]
        if self.count:
            cmd.extend(['-c', str(self.count)])
        if self.interval:
            cmd.extend(['-i', str(self.interval)])
        cmd.append(self.address)
        self.proc = RootHelperProcess(cmd, namespace=self.namespace)

    def stop(self):
        if self.proc and self.proc.is_running:
            self.proc.kill(signal.SIGINT)
            self._wait_for_death()
            self._parse_stats()

    def wait(self):
        if self.count:
            self._wait_for_death()
            self._parse_stats()
        else:
            raise RuntimeError("Pinger is running infinitely, use stop() "
                               "first")


class NetcatTester(object):
    TCP = n_const.PROTO_NAME_TCP
    UDP = n_const.PROTO_NAME_UDP
    SCTP = n_const.PROTO_NAME_SCTP
    VERSION_TO_ALL_ADDRESS = {
        n_const.IP_VERSION_4: '0.0.0.0',
        n_const.IP_VERSION_6: '::',
    }

    def __init__(self, client_namespace, server_namespace, address,
                 dst_port, protocol, server_address=None, src_port=None):

        """Initialize NetcatTester

        Tool for testing connectivity on transport layer using netcat
        executable.

        The processes are spawned lazily.

        :param client_namespace: Namespace in which netcat process that
                                 connects to other netcat will be spawned
        :param server_namespace: Namespace in which listening netcat process
                                 will be spawned
        :param address: Server address from client point of view
        :param dst_port: Port on which netcat listens
        :param protocol: Transport protocol, either 'tcp', 'udp' or 'sctp'
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

        try:
            self.client_process.writeline(testing_string)
            message = self.server_process.read_stdout(READ_TIMEOUT).strip()
            self.server_process.writeline(message)
            message = self.client_process.read_stdout(READ_TIMEOUT).strip()
        except ConnectionError as e:
            LOG.debug("Error: %s occurred during connectivity test.", e)
            message = ""

        return message == testing_string

    def test_no_connectivity(self, respawn=False):
        try:
            return not self.test_connectivity(respawn)
        except RuntimeError:
            return True

    def _spawn_nc_in_namespace(self, namespace, address, listen=False):
        cmd = ['ncat', address, self.dst_port]
        if self.protocol == self.UDP:
            cmd.append('-u')
        elif self.protocol == self.SCTP:
            cmd.append('--sctp')

        if listen:
            cmd.append('-l')
            if self.protocol in (self.TCP, self.SCTP):
                cmd.append('-k')
        else:
            cmd.extend(['-w', '20'])
            if self.src_port:
                cmd.extend(['-p', self.src_port])
        proc = RootHelperProcess(cmd, namespace=namespace)
        return proc

    def stop_processes(self, skip_errors=None):
        for proc_attr in ('_client_process', '_server_process'):
            proc = getattr(self, proc_attr)
            if proc:
                try:
                    if proc.poll() is None:
                        proc.kill(skip_errors=skip_errors)
                        proc.wait()
                except n_exc.ProcessExecutionError as exc:
                    for skip_error in skip_errors:
                        if skip_error in str(exc):
                            break
                    else:
                        raise exc
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
        self.ip_wrapper = ip.ensure_namespace(self.name)
        self.addCleanup(self.destroy)

    def destroy(self):
        # TODO(ralonsoh): once the issue in LP#1838793 is properly fixed, we
        # can remove this workaround (TestTimer context).
        with helpers.TestTimer(5):
            try:
                if self.ip_wrapper.netns.exists(self.name):
                    for pid in ip_lib.list_namespace_pids(self.name):
                        utils.kill_process(pid, signal.SIGKILL,
                                           run_as_root=True)
                    self.ip_wrapper.netns.delete(self.name)
            except helpers.TestTimerTimeout:
                LOG.warning('Namespace %s was not deleted due to a timeout.',
                            self.name)


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
            if (port.namespace is None or
                    ip_wrapper.netns.exists(port.namespace)):
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
            return common_utils.get_rand_device_name(VETH0_PREFIX)
        if name.startswith(VETH1_PREFIX):
            return common_utils.get_rand_device_name(VETH1_PREFIX)
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
        if (ip_lib.network_namespace_exists(self.ip_dev.namespace) or
                self.ip_dev.namespace is None):
            try:
                self.ip_dev.link.delete()
            except RuntimeError:
                pass


class PortFixture(fixtures.Fixture, metaclass=abc.ABCMeta):
    """Create a port.

    :ivar port: created port
    :type port: IPDevice
    :ivar bridge: port bridge
    """

    def __init__(self, bridge=None, namespace=None, mac=None, port_id=None):
        super(PortFixture, self).__init__()
        self.bridge = bridge
        self.namespace = namespace
        self.mac = (mac or
                    db_base.DbBasePluginCommon._generate_macs()[0])
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
    def get(cls, bridge, namespace=None, mac=None, port_id=None,
            hybrid_plug=False):
        """Deduce PortFixture class from bridge type and instantiate it."""
        if isinstance(bridge, ovs_lib.OVSBridge):
            return OVSPortFixture(bridge, namespace, mac, port_id, hybrid_plug)
        if isinstance(bridge, bridge_lib.BridgeDevice):
            return LinuxBridgePortFixture(bridge, namespace, mac, port_id)
        if isinstance(bridge, VethBridge):
            return VethPortFixture(bridge, namespace)
        tools.fail('Unexpected bridge type: %s' % type(bridge))

    def set_port_mac_address(self):

        def set_mac_address():
            self.port.link.set_address(self.mac)
            return self.port.link.address.lower() == self.mac.lower()

        try:
            common_utils.wait_until_true(set_mac_address, timeout=10)
        except common_utils.WaitTimeout:
            LOG.error("MAC address of the port %s not set properly. "
                      "Requested MAC: %s; Actual MAC: %s",
                      self.port, self.mac, self.port.link.address)


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


class OVSTrunkBridgeFixture(OVSBridgeFixture):
    """This bridge doesn't generate the name."""
    def _setUp(self):
        ovs = ovs_lib.BaseOVS()
        self.bridge = ovs.add_bridge(self.prefix)
        self.addCleanup(self.bridge.destroy)


class OVSTrunkBridgeFixtureTrunkBridge(fixtures.Fixture):

    def __init__(self, trunk_id):
        super(OVSTrunkBridgeFixtureTrunkBridge, self).__init__()
        self.trunk_id = trunk_id

    def _setUp(self):
        self.bridge = trunk_manager.TrunkBridge(self.trunk_id)
        self.bridge.create()
        self.addCleanup(self.bridge.destroy)


class OVSPortFixture(PortFixture):
    NIC_NAME_LEN = 14

    def __init__(self, bridge=None, namespace=None, mac=None, port_id=None,
                 hybrid_plug=False):
        super(OVSPortFixture, self).__init__(bridge, namespace, mac, port_id)
        self.hybrid_plug = hybrid_plug
        self.vlan_tag = None

    def _create_bridge_fixture(self):
        return OVSBridgeFixture()

    def _setUp(self):
        super(OVSPortFixture, self)._setUp()

        # because in some tests this port can be used to providing connection
        # between linuxbridge agents and vlan_id can be also added to this
        # device name it has to be max LB_DEVICE_NAME_MAX_LEN long
        port_name = common_utils.get_rand_name(
            LB_DEVICE_NAME_MAX_LEN,
            PORT_PREFIX
        )

        if self.hybrid_plug:
            self.hybrid_plug_port(port_name)
        else:
            self.plug_port(port_name)

    def plug_port(self, port_name):
        # TODO(jlibosva): Don't use interface driver for fullstack fake
        # machines as the port should be treated by OVS agent and not by
        # external party
        interface_config = cfg.ConfigOpts()
        config.register_interface_opts(interface_config)
        ovs_interface = interface.OVSInterfaceDriver(interface_config)
        # NOTE(slaweq): for OVS implementation normally there would be DEAD
        # VLAN tag set for port and we would need to remove it here as it is
        # needed during the tests. But to avoid setting and removing tag, we
        # can simply mock _set_port_dead method so port will not be tagged with
        # DEAD_VLAN tag initially
        with mock.patch.object(ovs_lib.OVSBridge, '_set_port_dead'):
            ovs_interface.plug_new(
                None,
                self.port_id,
                port_name,
                self.mac,
                bridge=self.bridge.br_name,
                namespace=self.namespace)
        self.addCleanup(self.bridge.delete_port, port_name)
        self.port = ip_lib.IPDevice(port_name, self.namespace)

    def hybrid_plug_port(self, port_name):
        """Plug port with linux bridge in the middle.

        """
        ip_wrapper = ip_lib.IPWrapper(self.namespace)
        qvb_name, qvo_name = self._get_veth_pair_names(self.port_id)
        qvb, qvo = self.useFixture(NamedVethFixture(qvb_name, qvo_name)).ports
        qvb.link.set_up()
        qvo.link.set_up()
        qbr_name = self._get_br_name(self.port_id)
        self.qbr = self.useFixture(
            LinuxBridgeFixture(qbr_name,
                               namespace=None,
                               prefix_is_full_name=True)).bridge
        self.qbr.link.set_up()
        self.qbr.setfd(0)
        self.qbr.disable_stp()
        self.qbr.addif(qvb_name)
        qvo_attrs = ('external_ids', {'iface-id': self.port_id,
                                      'iface-status': 'active',
                                      'attached-mac': self.mac})
        self.bridge.add_port(qvo_name, qvo_attrs)

        # NOTE(jlibosva): Create fake vm port, instead of tap device, we use
        # veth pair here in order to be able to attach it to linux bridge in
        # root namespace. Name with tap is in root namespace and its peer is in
        # the namespace
        hybrid_port_name = iptables_firewall.get_hybrid_port_name(self.port_id)
        bridge_port, self.port = self.useFixture(
            NamedVethFixture(hybrid_port_name)).ports
        self.addCleanup(self.port.link.delete)
        ip_wrapper.add_device_to_namespace(self.port)
        bridge_port.link.set_up()
        self.qbr.addif(bridge_port.name)

        self.set_port_mac_address()
        self.port.link.set_up()

    # NOTE(jlibosva): Methods below are taken from nova.virt.libvirt.vif
    def _get_br_name(self, iface_id):
        return ("qbr" + iface_id)[:self.NIC_NAME_LEN]

    def _get_veth_pair_names(self, iface_id):
        return (("qvb%s" % iface_id)[:self.NIC_NAME_LEN],
                ("qvo%s" % iface_id)[:self.NIC_NAME_LEN])


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
            self.veth_fixture = self.useFixture(
                NamedVethFixture(veth0_prefix=br_port_name))
        else:
            self.veth_fixture = self.useFixture(VethFixture())
        self.br_port, self.port = self.veth_fixture.ports

        self.set_port_mac_address()

        # bridge side
        br_ip_wrapper = ip_lib.IPWrapper(self.bridge.namespace)
        br_ip_wrapper.add_device_to_namespace(self.br_port)
        self.bridge.addif(self.br_port.name)
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
        self.unallocated_ports = list(self.ports)

    def allocate_port(self):
        try:
            return self.unallocated_ports.pop()
        except IndexError:
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
