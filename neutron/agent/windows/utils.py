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

from neutron_lib.utils import helpers
from oslo_log import log as logging
from oslo_utils import encodeutils

from neutron._i18n import _
from neutron.agent.windows import winutils

LOG = logging.getLogger(__name__)


def create_process(cmd, addl_env=None):
    cmd = list(map(str, cmd))

    LOG.debug("Running command: %s", cmd)
    env = os.environ.copy()
    if addl_env:
        env.update(addl_env)

    obj = winutils.ProcessWithNamedPipes(cmd, env)

    return obj, cmd


def execute(cmd, process_input=None, addl_env=None,
            check_exit_code=True, return_stderr=False, log_fail_as_error=True,
            extra_ok_codes=None, run_as_root=False, do_decode=True):

    if process_input is not None:
        _process_input = encodeutils.to_utf8(process_input)
    else:
        _process_input = None
    obj, cmd = create_process(cmd, addl_env=addl_env)
    _stdout, _stderr = obj.communicate(_process_input)
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
        raise RuntimeError(m)

    return (_stdout, _stderr) if return_stderr else _stdout
