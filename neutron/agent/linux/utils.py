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

import glob
import grp
from http import client as httplib
import os
import pwd
import shlex
import socket
import threading
import time

import eventlet
from eventlet.green import subprocess
from neutron_lib import exceptions
from neutron_lib.utils import helpers
from oslo_config import cfg
from oslo_log import log as logging
from oslo_rootwrap import client
from oslo_utils import encodeutils
from oslo_utils import excutils
from oslo_utils import fileutils

from neutron._i18n import _
from neutron.agent.linux import xenapi_root_helper
from neutron.common import utils
from neutron.conf.agent import common as config
from neutron.privileged.agent.linux import utils as priv_utils
from neutron import wsgi


LOG = logging.getLogger(__name__)


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
                if (xenapi_root_helper.ROOT_HELPER_DAEMON_TOKEN ==
                        cfg.CONF.AGENT.root_helper_daemon):
                    cls.__client = xenapi_root_helper.XenAPIClient()
                else:
                    cls.__client = client.Client(
                        shlex.split(cfg.CONF.AGENT.root_helper_daemon))
            return cls.__client


def addl_env_args(addl_env):
    """Build arguments for adding additional environment vars with env"""

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
    cmd = list(map(str, addl_env_args(addl_env) + cmd))
    if run_as_root:
        cmd = shlex.split(config.get_root_helper(cfg.CONF)) + cmd
    LOG.debug("Running command: %s", cmd)
    obj = utils.subprocess_popen(cmd, shell=False,
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)

    return obj, cmd


def execute_rootwrap_daemon(cmd, process_input, addl_env):
    cmd = list(map(str, addl_env_args(addl_env) + cmd))
    # NOTE(twilson) oslo_rootwrap.daemon will raise on filter match
    # errors, whereas oslo_rootwrap.cmd converts them to return codes.
    # In practice, no neutron code should be trying to execute something that
    # would throw those errors, and if it does it should be fixed as opposed to
    # just logging the execution error.
    LOG.debug("Running command (rootwrap daemon): %s", cmd)
    client = RootwrapDaemonHelper.get_client()
    try:
        return client.execute(cmd, process_input)
    except Exception:
        with excutils.save_and_reraise_exception():
            LOG.error("Rootwrap error running command: %s", cmd)


def execute(cmd, process_input=None, addl_env=None,
            check_exit_code=True, return_stderr=False, log_fail_as_error=True,
            extra_ok_codes=None, run_as_root=False):
    try:
        if process_input is not None:
            _process_input = encodeutils.to_utf8(process_input)
        else:
            _process_input = None
        if run_as_root and cfg.CONF.AGENT.root_helper_daemon:
            returncode, _stdout, _stderr = (
                execute_rootwrap_daemon(cmd, process_input, addl_env))
        else:
            obj, cmd = create_process(cmd, run_as_root=run_as_root,
                                      addl_env=addl_env)
            _stdout, _stderr = obj.communicate(_process_input)
            returncode = obj.returncode
            obj.stdin.close()
        _stdout = helpers.safe_decode_utf8(_stdout)
        _stderr = helpers.safe_decode_utf8(_stderr)

        extra_ok_codes = extra_ok_codes or []
        if returncode and returncode not in extra_ok_codes:
            msg = _("Exit code: %(returncode)d; "
                    "Cmd: %(cmd)s; "
                    "Stdin: %(stdin)s; "
                    "Stdout: %(stdout)s; "
                    "Stderr: %(stderr)s") % {
                        'returncode': returncode,
                        'cmd': cmd,
                        'stdin': process_input or '',
                        'stdout': _stdout,
                        'stderr': _stderr}

            if log_fail_as_error:
                LOG.error(msg)
            if check_exit_code:
                raise exceptions.ProcessExecutionError(msg,
                                                       returncode=returncode)

    finally:
        # NOTE(termie): this appears to be necessary to let the subprocess
        #               call clean something up in between calls, without
        #               it two execute calls in a row hangs the second one
        time.sleep(0)

    return (_stdout, _stderr) if return_stderr else _stdout


def find_child_pids(pid, recursive=False):
    """Retrieve a list of the pids of child processes of the given pid.

    It can also find all children through the hierarchy if recursive=True
    """
    try:
        raw_pids = execute(['ps', '--ppid', pid, '-o', 'pid='],
                           log_fail_as_error=False)
    except exceptions.ProcessExecutionError as e:
        # Unexpected errors are the responsibility of the caller
        with excutils.save_and_reraise_exception() as ctxt:
            # Exception has already been logged by execute
            no_children_found = e.returncode == 1
            if no_children_found:
                ctxt.reraise = False
                return []
    child_pids = [x.strip() for x in raw_pids.split('\n') if x.strip()]
    if recursive:
        for child in child_pids:
            child_pids = child_pids + find_child_pids(child, True)
    return child_pids


def find_parent_pid(pid):
    """Retrieve the pid of the parent process of the given pid.

    If the pid doesn't exist in the system, this function will return
    None
    """
    try:
        ppid = execute(['ps', '-o', 'ppid=', pid],
                       log_fail_as_error=False)
    except exceptions.ProcessExecutionError as e:
        # Unexpected errors are the responsibility of the caller
        with excutils.save_and_reraise_exception() as ctxt:
            # Exception has already been logged by execute
            no_such_pid = e.returncode == 1
            if no_such_pid:
                ctxt.reraise = False
                return
    return ppid.strip()


def get_process_count_by_name(name):
    """Find the process count by name."""
    try:
        out = execute(['ps', '-C', name, '-o', 'comm='],
                      log_fail_as_error=False)
    except exceptions.ProcessExecutionError:
        with excutils.save_and_reraise_exception(reraise=False):
            return 0
    return len(out.strip('\n').split('\n'))


def find_fork_top_parent(pid):
    """Retrieve the pid of the top parent of the given pid through a fork.

    This function will search the top parent with its same cmdline. If the
    given pid has no parent, its own pid will be returned
    """
    while True:
        ppid = find_parent_pid(pid)
        if (ppid and ppid != pid and
                pid_invoked_with_cmdline(ppid, get_cmdline_from_pid(pid))):
            pid = ppid
        else:
            return pid


def kill_process(pid, signal, run_as_root=False):
    """Kill the process with the given pid using the given signal."""
    try:
        execute(['kill', '-%d' % signal, pid], run_as_root=run_as_root)
    except exceptions.ProcessExecutionError:
        if process_is_running(pid):
            raise


def _get_conf_base(cfg_root, uuid, ensure_conf_dir):
    # TODO(mangelajo): separate responsibilities here, ensure_conf_dir
    #                  should be a separate function
    conf_dir = os.path.abspath(os.path.normpath(cfg_root))
    conf_base = os.path.join(conf_dir, uuid)
    if ensure_conf_dir:
        fileutils.ensure_tree(conf_dir, mode=0o755)
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
                LOG.error('Unable to convert value in %s', filename)
    except IOError as error:
        LOG.debug('Unable to access %(filename)s; Error: %(error)s',
                  {'filename': filename, 'error': error})


def remove_conf_files(cfg_root, uuid):
    conf_base = _get_conf_base(cfg_root, uuid, False)
    for file_path in glob.iglob("%s.*" % conf_base):
        os.unlink(file_path)


def get_root_helper_child_pid(pid, expected_cmd, run_as_root=False):
    """Get the first non root_helper child pid in the process hierarchy.

    If root helper was used, two or more processes would be created:

     - a root helper process (e.g. sudo myscript)
     - possibly a rootwrap script (e.g. neutron-rootwrap)
     - a child process (e.g. myscript)
     - possibly its child processes

    Killing the root helper process will leave the child process
    running, re-parented to init, so the only way to ensure that both
    die is to target the child process directly.
    """
    pid = str(pid)
    if run_as_root:
        while True:
            try:
                # We shouldn't have more than one child per process
                # so keep getting the children of the first one
                pid = find_child_pids(pid)[0]
            except IndexError:
                return  # We never found the child pid with expected_cmd

            # If we've found a pid with no root helper, return it.
            # If we continue, we can find transient children.
            if pid_invoked_with_cmdline(pid, expected_cmd):
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


def process_is_running(pid):
    """Find if the given PID is running in the system.

    """
    return pid and os.path.exists('/proc/%s' % pid)


def get_cmdline_from_pid(pid):
    if not process_is_running(pid):
        return []
    # NOTE(jh): Even after the above check, the process may terminate
    # before the open below happens
    try:
        with open('/proc/%s/cmdline' % pid, 'r') as f:
            cmdline = f.readline().split('\0')[:-1]
    except IOError:
        return []

    # NOTE(slaweq): sometimes it may happen that values in
    # /proc/{pid}/cmdline are separated by space instead of NUL char,
    # in such case we would have everything in one element of cmdline_args
    # list and it would not match to expected cmd so we need to try to
    # split it by spaces
    if len(cmdline) == 1:
        cmdline = cmdline[0].split(' ')

    LOG.debug("Found cmdline %s for process with PID %s.", cmdline, pid)
    return cmdline


def cmd_matches_expected(cmd, expected_cmd, process_name):
    if process_name and cmd and cmd[0] == process_name:
        # If Neutron has defined the title (setproctitle) of the running
        # process, the "ps" output will be "<process_name> (cmd)"
        cmd = cmd[1:]
        cmd[0] = cmd[0].strip('(')
        cmd[-1] = cmd[-1].strip(')')

    abs_cmd = remove_abs_path(cmd)
    abs_expected_cmd = remove_abs_path(expected_cmd)
    if abs_cmd != abs_expected_cmd:
        # Commands executed with #! are prefixed with the script
        # executable. Check for the expected cmd being a subset of the
        # actual cmd to cover this possibility.
        abs_cmd = remove_abs_path(abs_cmd[1:])
    return abs_cmd == abs_expected_cmd


def pid_invoked_with_cmdline(pid, expected_cmd, process_name=None):
    """Validate process with given pid is running with provided parameters

    """
    cmd = get_cmdline_from_pid(pid)
    return cmd_matches_expected(cmd, expected_cmd, process_name)


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
        fileutils.ensure_tree(dirname, mode=0o755)


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


def delete_if_exists(path, run_as_root=False):
    """Delete a path, executed as normal user or with elevated privileges"""
    if run_as_root:
        priv_utils.delete_if_exists(path)
    else:
        fileutils.delete_if_exists(path)


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
    def __init__(self, *args):
        # NOTE(yamahata): from eventlet v0.22 HttpProtocol.__init__
        # signature was changed by changeset of
        # 7f53465578543156e7251e243c0636e087a8445f
        # Both have server as last arg, but first arg(s) differ
        server = args[-1]

        # Because the caller is eventlet.wsgi.Server.process_request,
        # the number of arguments will dictate if it is new or old style.
        if len(args) == 2:
            conn_state = args[0]
            client_address = conn_state[0]
            if not client_address:
                conn_state[0] = ('<local>', 0)
            # base class is old-style, so super does not work properly
            eventlet.wsgi.HttpProtocol.__init__(self, conn_state, server)
        elif len(args) == 3:
            request = args[0]
            client_address = args[1]
            if not client_address:
                client_address = ('<local>', 0)
            # base class is old-style, so super does not work properly
            # NOTE: eventlet 0.22 or later changes the number of args to 2.
            # If we install eventlet 0.22 or later into a venv for pylint,
            # pylint complains this. Let's skip it. (bug 1791178)
            # pylint: disable=too-many-function-args
            eventlet.wsgi.HttpProtocol.__init__(
                self, request, client_address, server)
        else:
            eventlet.wsgi.HttpProtocol.__init__(self, *args)


class UnixDomainWSGIServer(wsgi.Server):
    def __init__(self, name, num_threads=None):
        self._socket = None
        self._launcher = None
        self._server = None
        super(UnixDomainWSGIServer, self).__init__(name, disable_ssl=True,
                                                   num_threads=num_threads)

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
                             log=logger,
                             log_format=cfg.CONF.wsgi_log_format)
