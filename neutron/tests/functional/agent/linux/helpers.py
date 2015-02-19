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

import eventlet

from neutron.agent.common import config
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils

CHILD_PROCESS_TIMEOUT = os.environ.get('OS_TEST_CHILD_PROCESS_TIMEOUT', 20)
CHILD_PROCESS_SLEEP = os.environ.get('OS_TEST_CHILD_PROCESS_SLEEP', 0.5)
READ_TIMEOUT = os.environ.get('OS_TEST_READ_TIMEOUT', 5)

SS_SOURCE_PORT_PATTERN = re.compile(
    r'^.*\s+\d+\s+.*:(?P<port>\d+)\s+[0-9:].*')


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


def wait_until_true(predicate, timeout=60, sleep=1, exception=None):
    """
    Wait until callable predicate is evaluated as True

    :param predicate: Callable deciding whether waiting should continue.
    Best practice is to instantiate predicate with functools.partial()
    :param timeout: Timeout in seconds how long should function wait.
    :param sleep: Polling interval for results in seconds.
    :param exception: Exception class for eventlet.Timeout.
    (see doc for eventlet.Timeout for more information)
    """
    with eventlet.timeout.Timeout(timeout, exception):
        while not predicate():
            eventlet.sleep(sleep)


def remove_abs_path(cmd):
    """Remove absolute path of executable in cmd

    Note: New instance of list is returned

    :param cmd: parsed shlex command (e.g. ['/bin/foo', 'param1', 'param two'])

    """
    if cmd and os.path.isabs(cmd[0]):
        cmd = list(cmd)
        cmd[0] = os.path.basename(cmd[0])

    return cmd


def get_cmdline_from_pid(pid):
    if pid is None or not os.path.exists('/proc/%s' % pid):
        return list()
    with open('/proc/%s/cmdline' % pid, 'r') as f:
        return f.readline().split('\0')[:-1]


def cmdlines_are_equal(cmd1, cmd2):
    """Validate provided lists containing output of /proc/cmdline are equal

    This function ignores absolute paths of executables in order to have
    correct results in case one list uses absolute path and the other does not.
    """
    cmd1 = remove_abs_path(cmd1)
    cmd2 = remove_abs_path(cmd2)
    return cmd1 == cmd2


def pid_invoked_with_cmdline(pid, expected_cmd):
    """Validate process with given pid is running with provided parameters

    """
    cmdline = get_cmdline_from_pid(pid)
    return cmdlines_are_equal(expected_cmd, cmdline)


class Pinger(object):
    def __init__(self, testcase, timeout=1, max_attempts=1):
        self.testcase = testcase
        self._timeout = timeout
        self._max_attempts = max_attempts

    def _ping_destination(self, src_namespace, dest_address):
        src_namespace.netns.execute(['ping', '-c', self._max_attempts,
                                     '-W', self._timeout, dest_address])

    def assert_ping_from_ns(self, src_ns, dst_ip):
        try:
            self._ping_destination(src_ns, dst_ip)
        except RuntimeError:
            self.testcase.fail("destination ip %(dst_ip)s is not replying "
                               "to ping from namespace %(src_ns)s" %
                               {'src_ns': src_ns.namespace, 'dst_ip': dst_ip})

    def assert_no_ping_from_ns(self, src_ns, dst_ip):
        try:
            self._ping_destination(src_ns, dst_ip)
            self.testcase.fail("destination ip %(dst_ip)s is replying to ping"
                               "from namespace %(src_ns)s, but it shouldn't" %
                               {'src_ns': src_ns.namespace, 'dst_ip': dst_ip})
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
            wait_until_true(poll_predicate, timeout, 0.1,
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
            if pid_invoked_with_cmdline(child_pid, self.cmd):
                return True

        wait_until_true(
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
