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

from eventlet.green import subprocess
from eventlet import greenthread
from oslo_log import log as logging

from neutron.common import utils

LOG = logging.getLogger(__name__)


def create_process(cmd, addl_env=None):
    cmd = map(str, cmd)

    LOG.debug("Running command: %s", cmd)
    env = os.environ.copy()
    if addl_env:
        env.update(addl_env)

    obj = utils.subprocess_popen(cmd, shell=False,
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 env=env,
                                 preexec_fn=None,
                                 close_fds=False)

    return obj, cmd


def execute(cmd, process_input=None, addl_env=None,
            check_exit_code=True, return_stderr=False, log_fail_as_error=True,
            extra_ok_codes=None, run_as_root=False):

    try:
        obj, cmd = create_process(cmd, addl_env=addl_env)
        _stdout, _stderr = obj.communicate(process_input)
        obj.stdin.close()
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

        if obj.returncode and log_fail_as_error:
            LOG.error(m)
        else:
            LOG.debug(m)

        if obj.returncode and check_exit_code:
            raise RuntimeError(m)
    finally:
        # NOTE(termie): this appears to be necessary to let the subprocess
        #               call clean something up in between calls, without
        #               it two execute calls in a row hangs the second one
        greenthread.sleep(0)

    return (_stdout, _stderr) if return_stderr else _stdout
