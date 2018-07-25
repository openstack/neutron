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

import os

import eventlet
from eventlet import tpool
from neutron_lib.utils import helpers
from oslo_log import log as logging
from oslo_utils import encodeutils

from neutron._i18n import _

LOG = logging.getLogger(__name__)

# subprocess.Popen will spawn two threads consuming stdout/stderr when passing
# data through stdin. We need to make sure that *native* threads will be used
# as pipes are blocking on Windows.
subprocess = eventlet.patcher.original('subprocess')
subprocess.threading = eventlet.patcher.original('threading')


def create_process(cmd, addl_env=None):
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

    return obj, cmd


def execute(cmd, process_input=None, addl_env=None, run_as_root=False):
    if process_input is not None:
        _process_input = encodeutils.to_utf8(process_input)
    else:
        _process_input = None
    obj, cmd = create_process(cmd, addl_env=addl_env)
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

    log_msg = m.strip().replace('\n', '; ')
    if obj.returncode:
        LOG.error(log_msg)

    if obj.returncode:
        raise RuntimeError(m)

    return (_stdout, _stderr)


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
