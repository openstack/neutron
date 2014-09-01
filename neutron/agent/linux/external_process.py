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

from oslo.config import cfg

from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)

OPTS = [
    cfg.StrOpt('external_pids',
               default='$state_path/external/pids',
               help=_('Location to store child pid files')),
]

cfg.CONF.register_opts(OPTS)


class ProcessManager(object):
    """An external process manager for Neutron spawned processes.

    Note: The manager expects uuid to be in cmdline.
    """
    def __init__(self, conf, uuid, root_helper='sudo',
                 namespace=None, service=None, pids_path=None):
        self.conf = conf
        self.uuid = uuid
        self.root_helper = root_helper
        self.namespace = namespace
        if service:
            self.service_pid_fname = 'pid.' + service
        else:
            self.service_pid_fname = 'pid'
        self.pids_path = pids_path or self.conf.external_pids

    def enable(self, cmd_callback, reload_cfg=False):
        if not self.active:
            cmd = cmd_callback(self.get_pid_file_name(ensure_pids_dir=True))

            ip_wrapper = ip_lib.IPWrapper(self.root_helper, self.namespace)
            ip_wrapper.netns.execute(cmd)
        elif reload_cfg:
            self.reload_cfg()

    def reload_cfg(self):
        self.disable('HUP')

    def disable(self, sig='9'):
        pid = self.pid

        if self.active:
            cmd = ['kill', '-%s' % (sig), pid]
            utils.execute(cmd, self.root_helper)
            # In the case of shutting down, remove the pid file
            if sig == '9':
                utils.remove_conf_file(self.pids_path,
                                       self.uuid,
                                       self.service_pid_fname)
        elif pid:
            LOG.debug('Process for %(uuid)s pid %(pid)d is stale, ignoring '
                      'signal %(signal)s', {'uuid': self.uuid, 'pid': pid,
                                            'signal': sig})
        else:
            LOG.debug('No process started for %s', self.uuid)

    def get_pid_file_name(self, ensure_pids_dir=False):
        """Returns the file name for a given kind of config file."""
        return utils.get_conf_file_name(self.pids_path,
                                        self.uuid,
                                        self.service_pid_fname,
                                        ensure_pids_dir)

    @property
    def pid(self):
        """Last known pid for this external process spawned for this uuid."""
        return utils.get_value_from_conf_file(self.pids_path,
                                              self.uuid,
                                              self.service_pid_fname,
                                              int)

    @property
    def active(self):
        pid = self.pid
        if pid is None:
            return False

        cmdline = '/proc/%s/cmdline' % pid
        try:
            with open(cmdline, "r") as f:
                return self.uuid in f.readline()
        except IOError:
            return False
