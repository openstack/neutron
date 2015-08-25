# Copyright 2012 Locaweb.
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

import fcntl
import glob
import grp
import httplib
import os
import pwd
import shlex
import socket
import struct
import tempfile
import threading

import eventlet
from eventlet.green import subprocess
from eventlet import greenthread
from oslo_config import cfg
from oslo_log import log as logging
from oslo_log import loggers
from oslo_rootwrap import client
from oslo_utils import excutils

from neutron.agent.common import config
from neutron.common import constants
from neutron.common import utils
from neutron.i18n import _LE
from neutron import wsgi


LOG = logging.getLogger(__name__)
config.register_root_helper(cfg.CONF)


class RootwrapDaemonHelper(object):
    __client = None
    __lock = threading.Lock()

    def __new__(cls):
        """There is no reason to instantiate this class"""
        raise NotImplementedError()

    @classmethod
    def get_client(cls):
        with cls.__lock:
            if cls.__client is None:
                cls.__client = client.Client(
                    shlex.split(cfg.CONF.AGENT.root_helper_daemon))
            return cls.__client


def addl_env_args(addl_env):
    """Build arugments for adding additional environment vars with env"""

    # NOTE (twilson) If using rootwrap, an EnvFilter should be set up for the
    # command instead of a CommandFilter.
    if addl_env is None:
        return []
    return ['env'] + ['%s=%s' % pair for pair in addl_env.items()]


def create_process(cmd, run_as_root=False, addl_env=None):
    """Create a process object for the given command.

    The return value will be a tuple of the process object and the
    list of command arguments used to create it.
    """
    cmd = map(str, addl_env_args(addl_env) + cmd)
    if run_as_root:
        cmd = shlex.split(config.get_root_helper(cfg.CONF)) + cmd
    LOG.debug("Running command: %s", cmd)
    obj = utils.subprocess_popen(cmd, shell=False,
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)

    return obj, cmd


def execute_rootwrap_daemon(cmd, process_input, addl_env):
    cmd = map(str, addl_env_args(addl_env) + cmd)
    # NOTE(twilson) oslo_rootwrap.daemon will raise on filter match
    # errors, whereas oslo_rootwrap.cmd converts them to return codes.
    # In practice, no neutron code should be trying to execute something that
    # would throw those errors, and if it does it should be fixed as opposed to
    # just logging the execution error.
    LOG.debug("Running command (rootwrap daemon): %s", cmd)
    client = RootwrapDaemonHelper.get_client()
    return client.execute(cmd, process_input)


def execute(cmd, process_input=None, addl_env=None,
            check_exit_code=True, return_stderr=False, log_fail_as_error=True,
            extra_ok_codes=None, run_as_root=False):
    try:
        if run_as_root and cfg.CONF.AGENT.root_helper_daemon:
            returncode, _stdout, _stderr = (
                execute_rootwrap_daemon(cmd, process_input, addl_env))
        else:
            obj, cmd = create_process(cmd, run_as_root=run_as_root,
                                      addl_env=addl_env)
            _stdout, _stderr = obj.communicate(process_input)
            returncode = obj.returncode
            obj.stdin.close()

        m = _("\nCommand: {cmd}\nExit code: {code}\nStdin: {stdin}\n"
              "Stdout: {stdout}\nStderr: {stderr}").format(
                  cmd=cmd,
                  code=returncode,
                  stdin=process_input or '',
                  stdout=_stdout,
                  stderr=_stderr)

        extra_ok_codes = extra_ok_codes or []
        if returncode and returncode in extra_ok_codes:
            returncode = None

        if returncode and log_fail_as_error:
            LOG.error(m)
        else:
            LOG.debug(m)

        if returncode and check_exit_code:
            raise RuntimeError(m)
    finally:
        # NOTE(termie): this appears to be necessary to let the subprocess
        #               call clean something up in between calls, without
        #               it two execute calls in a row hangs the second one
        greenthread.sleep(0)

    return (_stdout, _stderr) if return_stderr else _stdout


def get_interface_mac(interface):
    MAC_START = 18
    MAC_END = 24
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,
        struct.pack('256s', interface[:constants.DEVICE_NAME_MAX_LEN]))
    return ''.join(['%02x:' % ord(char)
                    for char in info[MAC_START:MAC_END]])[:-1]


def replace_file(file_name, data, file_mode=0o644):
    """Replaces the contents of file_name with data in a safe manner.

    First write to a temp file and then rename. Since POSIX renames are
    atomic, the file is unlikely to be corrupted by competing writes.

    We create the tempfile on the same device to ensure that it can be renamed.
    """

    base_dir = os.path.dirname(os.path.abspath(file_name))
    tmp_file = tempfile.NamedTemporaryFile('w+', dir=base_dir, delete=False)
    tmp_file.write(data)
    tmp_file.close()
    os.chmod(tmp_file.name, file_mode)
    os.rename(tmp_file.name, file_name)


def find_child_pids(pid):
    """Retrieve a list of the pids of child processes of the given pid."""

    try:
        raw_pids = execute(['ps', '--ppid', pid, '-o', 'pid='],
                           log_fail_as_error=False)
    except RuntimeError as e:
        # Unexpected errors are the responsibility of the caller
        with excutils.save_and_reraise_exception() as ctxt:
            # Exception has already been logged by execute
            no_children_found = 'Exit code: 1' in e.message
            if no_children_found:
                ctxt.reraise = False
                return []
    return [x.strip() for x in raw_pids.split('\n') if x.strip()]


def ensure_dir(dir_path):
    """Ensure a directory with 755 permissions mode."""
    if not os.path.isdir(dir_path):
        os.makedirs(dir_path, 0o755)


def _get_conf_base(cfg_root, uuid, ensure_conf_dir):
    #TODO(mangelajo): separate responsibilities here, ensure_conf_dir
    #                 should be a separate function
    conf_dir = os.path.abspath(os.path.normpath(cfg_root))
    conf_base = os.path.join(conf_dir, uuid)
    if ensure_conf_dir:
        ensure_dir(conf_dir)
    return conf_base


def get_conf_file_name(cfg_root, uuid, cfg_file, ensure_conf_dir=False):
    """Returns the file name for a given kind of config file."""
    conf_base = _get_conf_base(cfg_root, uuid, ensure_conf_dir)
    return "%s.%s" % (conf_base, cfg_file)


def get_value_from_file(filename, converter=None):

    try:
        with open(filename, 'r') as f:
            try:
                return converter(f.read()) if converter else f.read()
            except ValueError:
                LOG.error(_LE('Unable to convert value in %s'), filename)
    except IOError:
        LOG.debug('Unable to access %s', filename)


def get_value_from_conf_file(cfg_root, uuid, cfg_file, converter=None):
    """A helper function to read a value from one of a config file."""
    file_name = get_conf_file_name(cfg_root, uuid, cfg_file)
    return get_value_from_file(file_name, converter)


def remove_conf_files(cfg_root, uuid):
    conf_base = _get_conf_base(cfg_root, uuid, False)
    for file_path in glob.iglob("%s.*" % conf_base):
        os.unlink(file_path)


def get_root_helper_child_pid(pid, run_as_root=False):
    """
    Get the lowest child pid in the process hierarchy

    If root helper was used, two or more processes would be created:

     - a root helper process (e.g. sudo myscript)
     - possibly a rootwrap script (e.g. neutron-rootwrap)
     - a child process (e.g. myscript)

    Killing the root helper process will leave the child process
    running, re-parented to init, so the only way to ensure that both
    die is to target the child process directly.
    """
    pid = str(pid)
    if run_as_root:
        try:
            pid = find_child_pids(pid)[0]
        except IndexError:
            # Process is already dead
            return None
        while True:
            try:
                # We shouldn't have more than one child per process
                # so keep getting the children of the first one
                pid = find_child_pids(pid)[0]
            except IndexError:
                # Last process in the tree, return it
                break
    return pid


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
        return []
    with open('/proc/%s/cmdline' % pid, 'r') as f:
        return f.readline().split('\0')[:-1]


def cmd_matches_expected(cmd, expected_cmd):
    abs_cmd = remove_abs_path(cmd)
    abs_expected_cmd = remove_abs_path(expected_cmd)
    if abs_cmd != abs_expected_cmd:
        # Commands executed with #! are prefixed with the script
        # executable. Check for the expected cmd being a subset of the
        # actual cmd to cover this possibility.
        abs_cmd = remove_abs_path(abs_cmd[1:])
    return abs_cmd == abs_expected_cmd


def pid_invoked_with_cmdline(pid, expected_cmd):
    """Validate process with given pid is running with provided parameters

    """
    cmd = get_cmdline_from_pid(pid)
    return cmd_matches_expected(cmd, expected_cmd)


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


def ensure_directory_exists_without_file(path):
    dirname = os.path.dirname(path)
    if os.path.isdir(dirname):
        try:
            os.unlink(path)
        except OSError:
            with excutils.save_and_reraise_exception() as ctxt:
                if not os.path.exists(path):
                    ctxt.reraise = False
    else:
        ensure_dir(dirname)


def is_effective_user(user_id_or_name):
    """Returns True if user_id_or_name is effective user (id/name)."""
    euid = os.geteuid()
    if str(user_id_or_name) == str(euid):
        return True
    effective_user_name = pwd.getpwuid(euid).pw_name
    return user_id_or_name == effective_user_name


def is_effective_group(group_id_or_name):
    """Returns True if group_id_or_name is effective group (id/name)."""
    egid = os.getegid()
    if str(group_id_or_name) == str(egid):
        return True
    effective_group_name = grp.getgrgid(egid).gr_name
    return group_id_or_name == effective_group_name


class UnixDomainHTTPConnection(httplib.HTTPConnection):
    """Connection class for HTTP over UNIX domain socket."""
    def __init__(self, host, port=None, strict=None, timeout=None,
                 proxy_info=None):
        httplib.HTTPConnection.__init__(self, host, port, strict)
        self.timeout = timeout
        self.socket_path = cfg.CONF.metadata_proxy_socket

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if self.timeout:
            self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


class UnixDomainHttpProtocol(eventlet.wsgi.HttpProtocol):
    def __init__(self, request, client_address, server):
        if client_address == '':
            client_address = ('<local>', 0)
        # base class is old-style, so super does not work properly
        eventlet.wsgi.HttpProtocol.__init__(self, request, client_address,
                                            server)


class UnixDomainWSGIServer(wsgi.Server):
    def __init__(self, name):
        self._socket = None
        self._launcher = None
        self._server = None
        super(UnixDomainWSGIServer, self).__init__(name)

    def start(self, application, file_socket, workers, backlog, mode=None):
        self._socket = eventlet.listen(file_socket,
                                       family=socket.AF_UNIX,
                                       backlog=backlog)
        if mode is not None:
            os.chmod(file_socket, mode)

        self._launch(application, workers=workers)

    def _run(self, application, socket):
        """Start a WSGI service in a new green thread."""
        logger = logging.getLogger('eventlet.wsgi.server')
        eventlet.wsgi.server(socket,
                             application,
                             max_size=self.num_threads,
                             protocol=UnixDomainHttpProtocol,
                             log=loggers.WritableLogger(logger))
