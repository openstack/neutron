# Copyright (c) 2014 Red Hat, Inc.
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
import functools
import os
import random
import re
import select
import shlex
import subprocess

import fixtures
import netaddr

from neutron.agent.common import config
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.tests import tools

CHILD_PROCESS_TIMEOUT = os.environ.get('OS_TEST_CHILD_PROCESS_TIMEOUT', 20)
CHILD_PROCESS_SLEEP = os.environ.get('OS_TEST_CHILD_PROCESS_SLEEP', 0.5)
READ_TIMEOUT = os.environ.get('OS_TEST_READ_TIMEOUT', 5)

SS_SOURCE_PORT_PATTERN = re.compile(
    r'^.*\s+\d+\s+.*:(?P<port>\d+)\s+[0-9:].*')


class RecursivePermDirFixture(fixtures.Fixture):
    """Ensure at least perms permissions on directory and ancestors."""

    def __init__(self, directory, perms):
        super(RecursivePermDirFixture, self).__init__()
        self.directory = directory
        self.least_perms = perms

    def setUp(self):
        super(RecursivePermDirFixture, self).setUp()
        previous_directory = None
        current_directory = self.directory
        while previous_directory != current_directory:
            perms = os.stat(current_directory).st_mode
            if perms & self.least_perms != self.least_perms:
                os.chmod(current_directory, perms | self.least_perms)
                self.addCleanup(self.safe_chmod, current_directory, perms)
            previous_directory = current_directory
            current_directory = os.path.dirname(current_directory)

    def safe_chmod(self, path, mode):
        try:
            os.chmod(path, mode)
        except OSError:
            pass


def get_free_namespace_port(tcp=True, namespace=None):
    """Return an unused port from given namespace

    WARNING: This function returns a port that is free at the execution time of
             this function. If this port is used later for binding then there
             is a potential danger that port will be no longer free. It's up to
             the programmer to handle error if port is already in use.

    :param tcp: Return free port for TCP protocol if set to True, return free
                port for UDP protocol if set to False
    """
    if tcp:
        param = '-tna'
    else:
        param = '-una'

    ip_wrapper = ip_lib.IPWrapper(namespace=namespace)
    output = ip_wrapper.netns.execute(['ss', param])
    used_ports = _get_source_ports_from_ss_output(output)

    return get_unused_port(used_ports)


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


class Pinger(object):
    def __init__(self, namespace, timeout=1, max_attempts=1):
        self.namespace = namespace
        self._timeout = timeout
        self._max_attempts = max_attempts

    def _ping_destination(self, dest_address):
        ipversion = netaddr.IPAddress(dest_address).version
        ping_command = 'ping' if ipversion == 4 else 'ping6'
        self.namespace.netns.execute([ping_command, '-c', self._max_attempts,
                                      '-W', self._timeout, dest_address])

    def assert_ping(self, dst_ip):
        self._ping_destination(dst_ip)

    def assert_no_ping(self, dst_ip):
        try:
            self._ping_destination(dst_ip)
            tools.fail("destination ip %(dst_ip)s is replying to ping"
                       "from namespace %(ns)s, but it shouldn't" %
                       {'ns': self.namespace.namespace, 'dst_ip': dst_ip})
        except RuntimeError:
            pass


class RootHelperProcess(subprocess.Popen):
    def __init__(self, cmd, *args, **kwargs):
        for arg in ('stdin', 'stdout', 'stderr'):
            kwargs.setdefault(arg, subprocess.PIPE)
        self.namespace = kwargs.pop('namespace', None)
        self.run_as_root = kwargs.pop('run_as_root', False)
        self.cmd = cmd
        if self.namespace is not None:
            cmd = ['ip', 'netns', 'exec', self.namespace] + cmd
        if self.run_as_root:
            root_helper = config.get_root_helper(utils.cfg.CONF)
            cmd = shlex.split(root_helper) + cmd
        self.child_pid = None
        super(RootHelperProcess, self).__init__(cmd, *args, **kwargs)
        if self.run_as_root:
            self._wait_for_child_process()

    def kill(self):
        pid = self.child_pid or str(self.pid)
        utils.execute(['kill', '-9', pid], run_as_root=self.run_as_root)

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
                self.pid, run_as_root=self.run_as_root)
            if utils.pid_invoked_with_cmdline(child_pid, self.cmd):
                return True

        utils.wait_until_true(
            child_is_running,
            timeout,
            exception=RuntimeError("Process %s hasn't been spawned "
                                   "in %d seconds" % (self.cmd, timeout)))
        self.child_pid = utils.get_root_helper_child_pid(
            self.pid, run_as_root=self.run_as_root)


class NetcatTester(object):
    TESTING_STRING = 'foo'

    def __init__(self, client_namespace, server_namespace, server_address,
                 port, client_address=None, run_as_root=False, udp=False):
        self.client_namespace = client_namespace
        self.server_namespace = server_namespace
        self._client_process = None
        self._server_process = None
        # Use client_address to specify an address to connect client to that is
        # different from the one that server side is going to listen on (useful
        # when testing floating IPs)
        self.client_address = client_address or server_address
        self.server_address = server_address
        self.port = str(port)
        self.run_as_root = run_as_root
        self.udp = udp

    @property
    def client_process(self):
        if not self._client_process:
            if not self._server_process:
                self._spawn_server_process()
            self._client_process = self._spawn_nc_in_namespace(
                self.client_namespace.namespace,
                address=self.client_address)
        return self._client_process

    @property
    def server_process(self):
        if not self._server_process:
            self._spawn_server_process()
        return self._server_process

    def _spawn_server_process(self):
        self._server_process = self._spawn_nc_in_namespace(
            self.server_namespace.namespace,
            address=self.server_address,
            listen=True)

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
        cmd = ['nc', address, self.port]
        if self.udp:
            cmd.append('-u')
        if listen:
            cmd.append('-l')
            if not self.udp:
                cmd.append('-k')
        else:
            cmd.extend(['-w', '20'])
        proc = RootHelperProcess(cmd, namespace=namespace,
                                 run_as_root=self.run_as_root)
        return proc

    def stop_processes(self):
        for proc_attr in ('_client_process', '_server_process'):
            proc = getattr(self, proc_attr)
            if proc:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
                setattr(self, proc_attr, None)
