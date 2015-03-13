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

import shlex
import subprocess

from oslo_log import log as logging

LOG = logging.getLogger(__name__)


def copy_file_to_host(file_from, dest, host, username, pkey):
    dest = "%s@%s:%s" % (username, host, dest)
    cmd = "scp -v -o UserKnownHostsFile=/dev/null " \
          "-o StrictHostKeyChecking=no " \
          "-i %(pkey)s %(file1)s %(dest)s" % {'pkey': pkey,
                                              'file1': file_from,
                                              'dest': dest}
    args = shlex.split(cmd.encode('utf-8'))
    subprocess_args = {'stdout': subprocess.PIPE,
                       'stderr': subprocess.STDOUT}
    proc = subprocess.Popen(args, **subprocess_args)
    stdout, stderr = proc.communicate()
    if proc.returncode != 0:
        LOG.error(("Command {0} returned with exit status {1},"
                  "output {2}, error {3}").format(cmd, proc.returncode,
                                                  stdout, stderr))
    return stdout
