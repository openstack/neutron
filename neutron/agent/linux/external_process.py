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

import collections

import eventlet
from oslo.config import cfg

from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.openstack.common.gettextutils import _LE
from neutron.openstack.common import lockutils
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


OPTS = [
    cfg.StrOpt('external_pids',
               default='$state_path/external/pids',
               help=_('Location to store child pid files')),
    cfg.BoolOpt('check_child_processes', default=False,
                help=_("Periodically check child processes")),
    cfg.StrOpt('check_child_processes_action', default='respawn',
               choices=['respawn', 'exit'],
               help=_('Action to be executed when a child process dies')),
    cfg.IntOpt('check_child_processes_interval', default=60,
               help=_('Interval between checks of child process liveness '
                      '(seconds)')),
]


cfg.CONF.register_opts(OPTS)


class ProcessManager(object):
    """An external process manager for Neutron spawned processes.

    Note: The manager expects uuid to be in cmdline.
    """
    def __init__(self, conf, uuid, root_helper='sudo',
                 namespace=None, service=None, pids_path=None,
                 default_cmd_callback=None,
                 cmd_addl_env=None):

        self.conf = conf
        self.uuid = uuid
        self.root_helper = root_helper
        self.namespace = namespace
        self.default_cmd_callback = default_cmd_callback
        self.cmd_addl_env = cmd_addl_env
        self.pids_path = pids_path or self.conf.external_pids

        if service:
            self.service_pid_fname = 'pid.' + service
            self.service = service
        else:
            self.service_pid_fname = 'pid'
            self.service = 'default-service'

    def enable(self, cmd_callback=None, reload_cfg=False):
        if not self.active:
            if not cmd_callback:
                cmd_callback = self.default_cmd_callback
            cmd = cmd_callback(self.get_pid_file_name(ensure_pids_dir=True))

            ip_wrapper = ip_lib.IPWrapper(self.root_helper, self.namespace)
            ip_wrapper.netns.execute(cmd, addl_env=self.cmd_addl_env)
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


ServiceId = collections.namedtuple('ServiceId', ['uuid', 'service'])


class ProcessMonitor(object):

    def __init__(self, config, root_helper, resource_type, exit_handler):
        """Handle multiple process managers and watch over all of them.

        :param config: oslo config object with the agent configuration.
        :type config: oslo.config.ConfigOpts
        :param root_helper: root helper to be used with new ProcessManagers
        :type root_helper: str
        :param resource_type: can be dhcp, router, load_balancer, etc.
        :type resource_type: str
        :param exit_handler: function to execute when agent exit has to
                             be executed, it should take care of actual
                             exit
        :type exit_hanlder: function
        """
        self._config = config
        self._root_helper = root_helper
        self._resource_type = resource_type
        self._exit_handler = exit_handler

        self._process_managers = {}

        if self._config.check_child_processes:
            self._spawn_checking_thread()

    def enable(self, uuid, cmd_callback, namespace=None, service=None,
               reload_cfg=False, cmd_addl_env=None):
        """Creates a process and ensures that it is monitored.

        It will create a new ProcessManager and tie it to the uuid/service.
        """
        process_manager = ProcessManager(conf=self._config,
                                         uuid=uuid,
                                         root_helper=self._root_helper,
                                         namespace=namespace,
                                         service=service,
                                         default_cmd_callback=cmd_callback,
                                         cmd_addl_env=cmd_addl_env)

        process_manager.enable(reload_cfg=reload_cfg)
        service_id = ServiceId(uuid, service)
        self._process_managers[service_id] = process_manager

    def disable(self, uuid, namespace=None, service=None):
        """Disables the process and stops monitoring it."""
        service_id = ServiceId(uuid, service)
        process_manager = self._process_managers.pop(service_id, None)

        # we could be trying to disable a process_manager which was
        # started on a separate run of this agent, or during netns-cleanup
        # therefore we won't know about such uuid and we need to
        # build the process_manager to kill it
        if not process_manager:
            process_manager = ProcessManager(conf=self._config,
                                             uuid=uuid,
                                             root_helper=self._root_helper,
                                             namespace=namespace,
                                             service=service)

        process_manager.disable()

    def disable_all(self):
        for service_id in self._process_managers.keys():
            self.disable(uuid=service_id.uuid, service=service_id.service)

    def get_process_manager(self, uuid, service=None):
        """Returns a process manager for manipulation"""
        service_id = ServiceId(uuid, service)
        return self._process_managers.get(service_id)

    def _get_process_manager_attribute(self, attribute, uuid, service=None):
        process_manager = self.get_process_manager(uuid, service)
        if process_manager:
            return getattr(process_manager, attribute)
        else:
            return False

    def is_active(self, uuid, service=None):
        return self._get_process_manager_attribute('active', uuid, service)

    def get_pid(self, uuid, service=None):
        return self._get_process_manager_attribute('pid', uuid, service)

    def _spawn_checking_thread(self):
        eventlet.spawn(self._periodic_checking_thread)

    @lockutils.synchronized("_check_child_processes")
    def _check_child_processes(self):
        for service_id in self._process_managers:
            pm = self._process_managers.get(service_id)

            if pm and not pm.active:
                LOG.error(_LE("%(service)s for %(resource_type)s "
                              "with uuid %(uuid)s not found. "
                              "The process should not have died"),
                          {'service': pm.service,
                           'resource_type': self._resource_type,
                           'uuid': service_id.uuid})
                self._execute_action(service_id)
            eventlet.sleep(0)

    def _periodic_checking_thread(self):
        while True:
            eventlet.sleep(self._config.check_child_processes_interval)
            eventlet.spawn(self._check_child_processes)

    def _execute_action(self, service_id):
        action_function = getattr(
            self, "_%s_action" % self._config.check_child_processes_action)
        action_function(service_id)

    def _respawn_action(self, service_id):
        LOG.error(_LE("respawning %(service)s for uuid %(uuid)s"),
                  {'service': service_id.service,
                   'uuid': service_id.uuid})
        self._process_managers[service_id].enable()

    def _exit_action(self, service_id):
        LOG.error(_LE("Exiting agent as programmed in check_child_processes_"
                      "actions"))
        self._exit_handler(service_id.uuid, service_id.service)
