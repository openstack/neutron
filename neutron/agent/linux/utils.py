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
import os
import shlex
import socket
import struct
import tempfile

from eventlet.green import subprocess
from eventlet import greenthread
from oslo_config import cfg
from oslo_utils import excutils

from neutron.agent.common import config
from neutron.common import constants
from neutron.common import utils
from neutron.i18n import _LE
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)
config.register_root_helper(cfg.CONF)


def create_process(cmd, run_as_root=False, addl_env=None):
    """Create a process object for the given command.

    The return value will be a tuple of the process object and the
    list of command arguments used to create it.
    """
    if run_as_root:
        cmd = shlex.split(config.get_root_helper(cfg.CONF)) + cmd
    cmd = map(str, cmd)

    LOG.debug("Running command: %s", cmd)
    env = os.environ.copy()
    if addl_env:
        env.update(addl_env)

    obj = utils.subprocess_popen(cmd, shell=False,
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 env=env)

    return obj, cmd


def execute(cmd, process_input=None, addl_env=None,
            check_exit_code=True, return_stderr=False, log_fail_as_error=True,
            extra_ok_codes=None, run_as_root=False):
    try:
        obj, cmd = create_process(cmd, run_as_root=run_as_root,
                                  addl_env=addl_env)
        _stdout, _stderr = obj.communicate(process_input)
        obj.stdin.close()
        m = _("\nCommand: %(cmd)s\nExit code: %(code)s\nStdout: %(stdout)s\n"
              "Stderr: %(stderr)s") % {'cmd': cmd, 'code': obj.returncode,
                                       'stdout': _stdout, 'stderr': _stderr}

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


def get_interface_mac(interface):
    MAC_START = 18
    MAC_END = 24
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,
        struct.pack('256s', interface[:constants.DEVICE_NAME_MAX_LEN]))
    return ''.join(['%02x:' % ord(char)
                    for char in info[MAC_START:MAC_END]])[:-1]


def replace_file(file_name, data):
    """Replaces the contents of file_name with data in a safe manner.

    First write to a temp file and then rename. Since POSIX renames are
    atomic, the file is unlikely to be corrupted by competing writes.

    We create the tempfile on the same device to ensure that it can be renamed.
    """

    base_dir = os.path.dirname(os.path.abspath(file_name))
    tmp_file = tempfile.NamedTemporaryFile('w+', dir=base_dir, delete=False)
    tmp_file.write(data)
    tmp_file.close()
    os.chmod(tmp_file.name, 0o644)
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
