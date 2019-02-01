# Copyright 2015 Cloudbase Solutions.
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

import io
import os

import eventlet
from eventlet import tpool
from neutron_lib import exceptions
from neutron_lib.utils import helpers
from oslo_log import log as logging
from oslo_utils import encodeutils
import six

from neutron._i18n import _


if os.name == 'nt':
    import wmi

LOG = logging.getLogger(__name__)

# subprocess.Popen will spawn two threads consuming stdout/stderr when passing
# data through stdin. We need to make sure that *native* threads will be used
# as pipes are blocking on Windows.
subprocess = eventlet.patcher.original('subprocess')
subprocess.threading = eventlet.patcher.original('threading')


def create_process(cmd, run_as_root=False, addl_env=None,
                   tpool_proxy=True):
    cmd = list(map(str, cmd))

    LOG.debug("Running command: %s", cmd)
    env = os.environ.copy()
    if addl_env:
        env.update(addl_env)

    popen = subprocess.Popen
    obj = popen(cmd, shell=False,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                preexec_fn=None,
                close_fds=False)
    if tpool_proxy and eventlet.getcurrent().parent:
        # If we intend to access the process streams, we need to wrap this
        # in a tpool proxy object, avoding blocking other greenthreads.
        #
        # The 'file' type is not available on Python 3.x.
        file_type = getattr(six.moves.builtins, 'file', io.IOBase)
        obj = tpool.Proxy(obj, autowrap=(file_type, ))

    return obj, cmd


def _get_wmi_process(pid):
    if not pid:
        return None

    conn = wmi.WMI()
    processes = conn.Win32_Process(ProcessId=pid)
    if processes:
        return processes[0]
    return None


def kill_process(pid, signal, run_as_root=False):
    """Kill the process with the given pid using the given signal."""
    process = _get_wmi_process(pid)
    try:
        if process:
            process.Terminate()
    except Exception:
        if _get_wmi_process(pid):
            raise


def execute(cmd, process_input=None, addl_env=None,
            check_exit_code=True, return_stderr=False, log_fail_as_error=True,
            extra_ok_codes=None, run_as_root=False, do_decode=True):

    if process_input is not None:
        _process_input = encodeutils.to_utf8(process_input)
    else:
        _process_input = None
    obj, cmd = create_process(cmd, addl_env=addl_env, tpool_proxy=False)
    _stdout, _stderr = avoid_blocking_call(obj.communicate, _process_input)
    obj.stdin.close()
    _stdout = helpers.safe_decode_utf8(_stdout)
    _stderr = helpers.safe_decode_utf8(_stderr)

    m = _("\nCommand: %(cmd)s\nExit code: %(code)s\nStdin: %(stdin)s\n"
          "Stdout: %(stdout)s\nStderr: %(stderr)s") % \
        {'cmd': cmd,
         'code': obj.returncode,
         'stdin': process_input or '',
         'stdout': _stdout,
         'stderr': _stderr}

    extra_ok_codes = extra_ok_codes or []
    if obj.returncode and obj.returncode in extra_ok_codes:
        obj.returncode = None

    log_msg = m.strip().replace('\n', '; ')
    if obj.returncode and log_fail_as_error:
        LOG.error(log_msg)
    else:
        LOG.debug(log_msg)

    if obj.returncode and check_exit_code:
        raise exceptions.ProcessExecutionError(m, returncode=obj.returncode)

    return (_stdout, _stderr) if return_stderr else _stdout


def avoid_blocking_call(f, *args, **kwargs):
    """Ensure that the method "f" will not block other greenthreads.

    Performs the call to the function "f" received as parameter in a
    different thread using tpool.execute when called from a greenthread.
    This will ensure that the function "f" will not block other greenthreads.
    If not called from a greenthread, it will invoke the function "f" directly.
    The function "f" will receive as parameters the arguments "args" and
    keyword arguments "kwargs".
    """
    # Note that eventlet.getcurrent will always return a greenlet object.
    # In case of a greenthread, the parent greenlet will always be the hub
    # loop greenlet.
    if eventlet.getcurrent().parent:
        return tpool.execute(f, *args, **kwargs)
    else:
        return f(*args, **kwargs)


def get_root_helper_child_pid(pid, expected_cmd, run_as_root=False):
    # We don't use a root helper on Windows.
    return str(pid)


def process_is_running(pid):
    """Find if the given PID is running in the system."""
    return _get_wmi_process(pid) is not None


def pid_invoked_with_cmdline(pid, expected_cmd):
    process = _get_wmi_process(pid)
    if not process:
        return False

    command = process.CommandLine
    return command == " ".join(expected_cmd)
