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

import abc
import collections
import os.path
import six

import eventlet
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging

from neutron.agent.common import config as agent_cfg
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.i18n import _LE
from neutron.openstack.common import fileutils

LOG = logging.getLogger(__name__)


OPTS = [
    cfg.StrOpt('external_pids',
               default='$state_path/external/pids',
               help=_('Location to store child pid files')),
]


cfg.CONF.register_opts(OPTS)
agent_cfg.register_process_monitor_opts(cfg.CONF)


@six.add_metaclass(abc.ABCMeta)
class MonitoredProcess(object):
    @abc.abstractproperty
    def active(self):
        """Boolean representing the running state of the process."""

    @abc.abstractmethod
    def enable(self):
        """Enable the service, or respawn the process."""


class ProcessManager(MonitoredProcess):
    """An external process manager for Neutron spawned processes.

    Note: The manager expects uuid to be in cmdline.
    """
    def __init__(self, conf, uuid, namespace=None, service=None,
                 pids_path=None, default_cmd_callback=None,
                 cmd_addl_env=None, pid_file=None, run_as_root=False):

        self.conf = conf
        self.uuid = uuid
        self.namespace = namespace
        self.default_cmd_callback = default_cmd_callback
        self.cmd_addl_env = cmd_addl_env
        self.pids_path = pids_path or self.conf.external_pids
        self.pid_file = pid_file
        self.run_as_root = run_as_root

        if service:
            self.service_pid_fname = 'pid.' + service
            self.service = service
        else:
            self.service_pid_fname = 'pid'
            self.service = 'default-service'

        utils.ensure_dir(os.path.dirname(self.get_pid_file_name()))

    def enable(self, cmd_callback=None, reload_cfg=False):
        if not self.active:
            if not cmd_callback:
                cmd_callback = self.default_cmd_callback
            cmd = cmd_callback(self.get_pid_file_name())

            ip_wrapper = ip_lib.IPWrapper(namespace=self.namespace)
            ip_wrapper.netns.execute(cmd, addl_env=self.cmd_addl_env,
                                     run_as_root=self.run_as_root)
        elif reload_cfg:
            self.reload_cfg()

    def reload_cfg(self):
        self.disable('HUP')

    def disable(self, sig='9'):
        pid = self.pid

        if self.active:
            cmd = ['kill', '-%s' % (sig), pid]
            utils.execute(cmd, run_as_root=True)
            # In the case of shutting down, remove the pid file
            if sig == '9':
                fileutils.delete_if_exists(self.get_pid_file_name())
        elif pid:
            LOG.debug('Process for %(uuid)s pid %(pid)d is stale, ignoring '
                      'signal %(signal)s', {'uuid': self.uuid, 'pid': pid,
                                            'signal': sig})
        else:
            LOG.debug('No process started for %s', self.uuid)

    def get_pid_file_name(self):
        """Returns the file name for a given kind of config file."""
        if self.pid_file:
            return self.pid_file
        else:
            return utils.get_conf_file_name(self.pids_path,
                                            self.uuid,
                                            self.service_pid_fname)

    @property
    def pid(self):
        """Last known pid for this external process spawned for this uuid."""
        return utils.get_value_from_file(self.get_pid_file_name(), int)

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

    def __init__(self, config, resource_type):
        """Handle multiple process managers and watch over all of them.

        :param config: oslo config object with the agent configuration.
        :type config: oslo_config.ConfigOpts
        :param resource_type: can be dhcp, router, load_balancer, etc.
        :type resource_type: str
        """
        self._config = config
        self._resource_type = resource_type

        self._monitored_processes = {}

        if self._config.AGENT.check_child_processes_interval:
            self._spawn_checking_thread()

    def register(self, uuid, service_name, monitored_process):
        """Start monitoring a process.

        The given monitored_process will be tied to it's uuid+service_name
        replacing the old one if it existed already.

        The monitored_process should be enabled before registration,
        otherwise ProcessMonitor could try to enable the process itself,
        which could lead to double enable and if unlucky enough, two processes
        running, and also errors in the logs.

        :param uuid: An ID of the resource for which the process is running.
        :param service_name: A logical service name for this process monitor,
                             so the same uuid provided via process manager
                             can reference several different services.
        :param monitored_process: MonitoredProcess we want to monitor.
        """

        service_id = ServiceId(uuid, service_name)
        self._monitored_processes[service_id] = monitored_process

    def unregister(self, uuid, service_name):
        """Stop monitoring a process.

        The uuid+service_name will be removed from the monitored processes.

        The service must be disabled **after** unregistering, otherwise if
        process monitor checks after you disable the process, and before
        you unregister it, the process will be respawned, and left orphaned
        into the system.

        :param uuid: An ID of the resource for which the process is running.
        :param service_name: A logical service name for this process monitor,
                             so the same uuid provided via process manager
                             can reference several different services.
        """

        service_id = ServiceId(uuid, service_name)
        self._monitored_processes.pop(service_id, None)

    def stop(self):
        """Stop the process monitoring.

        This method will stop the monitoring thread, but no monitored
        process will be stopped.
        """
        self._monitor_processes = False

    def _spawn_checking_thread(self):
        self._monitor_processes = True
        eventlet.spawn(self._periodic_checking_thread)

    @lockutils.synchronized("_check_child_processes")
    def _check_child_processes(self):
        # we build the list of keys before iterating in the loop to cover
        # the case where other threads add or remove items from the
        # dictionary which otherwise will cause a RuntimeError
        for service_id in list(self._monitored_processes):
            pm = self._monitored_processes.get(service_id)

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
        while self._monitor_processes:
            eventlet.sleep(self._config.AGENT.check_child_processes_interval)
            eventlet.spawn(self._check_child_processes)

    def _execute_action(self, service_id):
        action = self._config.AGENT.check_child_processes_action
        action_function = getattr(self, "_%s_action" % action)
        action_function(service_id)

    def _respawn_action(self, service_id):
        LOG.error(_LE("respawning %(service)s for uuid %(uuid)s"),
                  {'service': service_id.service,
                   'uuid': service_id.uuid})
        self._monitored_processes[service_id].enable()

    def _exit_action(self, service_id):
        LOG.error(_LE("Exiting agent as programmed in check_child_processes_"
                      "actions"))
        self._exit_handler(service_id.uuid, service_id.service)

    def _exit_handler(self, uuid, service):
        """This is an exit handler for the ProcessMonitor.

        It will be called if the administrator configured the exit action in
        check_child_processes_actions, and one of our external processes die
        unexpectedly.
        """
        LOG.error(_LE("Exiting agent because of a malfunction with the "
                      "%(service)s process identified by uuid %(uuid)s"),
                  {'service': service, 'uuid': uuid})
        raise SystemExit(1)
