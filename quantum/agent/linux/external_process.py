# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 New Dream Network, LLC (DreamHost)
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
# @author: Mark McClain, DreamHost

import os

from oslo.config import cfg

from quantum.agent.linux import ip_lib
from quantum.agent.linux import utils
from quantum.openstack.common import log as logging

LOG = logging.getLogger(__name__)

OPTS = [
    cfg.StrOpt('external_pids',
               default='$state_path/external/pids',
               help=_('Location to store child pid files')),
]

cfg.CONF.register_opts(OPTS)


class ProcessManager(object):
    """An external process manager for Quantum spawned processes.

    Note: The manager expects uuid to be in cmdline.
    """
    def __init__(self, conf, uuid, root_helper='sudo', namespace=None):
        self.conf = conf
        self.uuid = uuid
        self.root_helper = root_helper
        self.namespace = namespace

    def enable(self, cmd_callback):
        if not self.active:
            cmd = cmd_callback(self.get_pid_file_name(ensure_pids_dir=True))

            if self.namespace:
                ip_wrapper = ip_lib.IPWrapper(self.root_helper, self.namespace)
                ip_wrapper.netns.execute(cmd)
            else:
                # For normal sudo prepend the env vars before command
                utils.execute(cmd, self.root_helper)

    def disable(self):
        pid = self.pid

        if self.active:
            cmd = ['kill', '-9', pid]
            utils.execute(cmd, self.root_helper)
        elif pid:
            LOG.debug(_('Process for %(uuid)s pid %(pid)d is stale, ignoring '
                        'command'), {'uuid': self.uuid, 'pid': pid})
        else:
            LOG.debug(_('No process started for %s'), self.uuid)

    def get_pid_file_name(self, ensure_pids_dir=False):
        """Returns the file name for a given kind of config file."""
        pids_dir = os.path.abspath(os.path.normpath(self.conf.external_pids))
        if ensure_pids_dir and not os.path.isdir(pids_dir):
            os.makedirs(pids_dir, 0755)

        return os.path.join(pids_dir, self.uuid + '.pid')

    @property
    def pid(self):
        """Last known pid for this external process spawned for this uuid."""
        file_name = self.get_pid_file_name()
        msg = _('Error while reading %s')

        try:
            with open(file_name, 'r') as f:
                return int(f.read())
        except IOError:
            msg = _('Unable to access %s')
        except ValueError:
            msg = _('Unable to convert value in %s')

        LOG.debug(msg, file_name)
        return None

    @property
    def active(self):
        pid = self.pid
        if pid is None:
            return False

        cmd = ['cat', '/proc/%s/cmdline' % pid]
        try:
            return self.uuid in utils.execute(cmd, self.root_helper)
        except RuntimeError:
            return False
