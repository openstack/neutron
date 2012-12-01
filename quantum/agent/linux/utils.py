# vim: tabstop=4 shiftwidth=4 softtabstop=4

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
#
# @author: Juliano Martinez, Locaweb.

import fcntl
import os
import shlex
import signal
import socket
import struct

from eventlet.green import subprocess

from quantum.common import utils
from quantum.openstack.common import log as logging


LOG = logging.getLogger(__name__)


def execute(cmd, root_helper=None, process_input=None, addl_env=None,
            check_exit_code=True, return_stderr=False):
    if root_helper:
        cmd = shlex.split(root_helper) + cmd
    cmd = map(str, cmd)

    LOG.debug(_("Running command: %s"), cmd)
    env = os.environ.copy()
    if addl_env:
        env.update(addl_env)
    obj = utils.subprocess_popen(cmd, shell=False,
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 env=env)

    _stdout, _stderr = (process_input and
                        obj.communicate(process_input) or
                        obj.communicate())
    obj.stdin.close()
    m = _("\nCommand: %(cmd)s\nExit code: %(code)s\nStdout: %(stdout)r\n"
          "Stderr: %(stderr)r") % {'cmd': cmd, 'code': obj.returncode,
                                   'stdout': _stdout, 'stderr': _stderr}
    LOG.debug(m)
    if obj.returncode and check_exit_code:
        raise RuntimeError(m)

    return return_stderr and (_stdout, _stderr) or _stdout


def get_interface_mac(interface):
    DEVICE_NAME_LEN = 15
    MAC_START = 18
    MAC_END = 24
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,
                       struct.pack('256s', interface[:DEVICE_NAME_LEN]))
    return ''.join(['%02x:' % ord(char)
                    for char in info[MAC_START:MAC_END]])[:-1]
