# Copyright 2011 VMware, Inc
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

import inspect
import os
import secrets

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import context
from neutron_lib.db import api as session
from neutron_lib.plugins import directory
from neutron_lib import rpc as n_rpc
from neutron_lib import worker as base_worker
from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_messaging import server as rpc_server
from oslo_service import loopingcall
from oslo_service import service as common_service
from oslo_utils import excutils
from oslo_utils import importutils
import psutil

from neutron._i18n import _
from neutron.common import config
from neutron.common import profiler
from neutron.conf import service
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import worker as \
    ovn_worker
from neutron import worker as neutron_worker


service.register_service_opts(service.SERVICE_OPTS)
service.register_service_opts(service.RPC_EXTRA_OPTS)

LOG = logging.getLogger(__name__)


class RpcWorker(neutron_worker.NeutronBaseWorker):
    """Wraps a worker to be handled by ProcessLauncher"""
    start_listeners_method = 'start_rpc_listeners'
    desc = 'rpc worker'

    def __init__(self, plugins, worker_process_count=1):
        super().__init__(
            worker_process_count=worker_process_count,
            desc=self.desc,
        )

        self._plugins = plugins
        self._servers = []

    def start(self):
        super().start(desc=self.desc)
        for plugin in self._plugins:
            if hasattr(plugin, self.start_listeners_method):
                try:
                    servers = getattr(plugin, self.start_listeners_method)()
                except NotImplementedError:
                    continue
                self._servers.extend(servers)

    def wait(self):
        try:
            self._wait()
        except Exception:
            LOG.exception('done with wait')
            raise

    def _wait(self):
        LOG.debug('calling RpcWorker wait()')
        for server in self._servers:
            if isinstance(server, rpc_server.MessageHandlingServer):
                LOG.debug('calling wait on %s', server)
                server.wait()
            else:
                LOG.debug('NOT calling wait on %s', server)
        LOG.debug('returning from RpcWorker wait()')

    def stop(self):
        LOG.debug('calling RpcWorker stop()')
        for server in self._servers:
            if isinstance(server, rpc_server.MessageHandlingServer):
                LOG.debug('calling stop on %s', server)
                server.stop()

    @staticmethod
    def reset():
        config.reset_service()


class RpcReportsWorker(RpcWorker):
    start_listeners_method = 'start_rpc_state_reports_listener'
    desc = 'rpc reports worker'


def _get_worker_count():
    # Start with the number of CPUs
    num_workers = processutils.get_worker_count()

    # Now don't use more than half the system memory, assuming
    # a steady-state bloat of around 2GB.
    mem = psutil.virtual_memory()
    mem_workers = int(mem.total / (2 * 1024 * 1024 * 1024))
    num_workers = min(num_workers, mem_workers)

    # And just in case, always at least one.
    if num_workers <= 0:
        num_workers = 1

    return num_workers


def _get_rpc_workers(plugin=None):
    if plugin is None:
        plugin = directory.get_plugin()
    service_plugins = directory.get_plugins().values()

    workers = cfg.CONF.rpc_workers
    if workers is None:
        # By default, half as many rpc workers as api workers
        workers = int(_get_api_workers() / 2)
        workers = max(workers, 1)

    # If workers > 0 then start_rpc_listeners would be called in a
    # subprocess and we cannot simply catch the NotImplementedError.  It is
    # simpler to check this up front by testing whether the plugin supports
    # multiple RPC workers.
    if not plugin.rpc_workers_supported():
        LOG.debug("Active plugin doesn't implement start_rpc_listeners")
        if workers > 0:
            LOG.error("'rpc_workers = %d' ignored because "
                      "start_rpc_listeners is not implemented.",
                      workers)
        raise NotImplementedError()

    rpc_workers = []

    if workers > 0:
        # passing service plugins only, because core plugin is among them
        rpc_workers.append(
            RpcWorker(service_plugins, worker_process_count=workers))
    else:
        LOG.warning('No rpc workers are launched. Make sure no agent is used '
                    'in this deployment.')

    if (cfg.CONF.rpc_state_report_workers > 0 and
            plugin.rpc_state_report_workers_supported()):
        rpc_workers.append(
            RpcReportsWorker(
                [plugin],
                worker_process_count=cfg.CONF.rpc_state_report_workers
            )
        )
    return rpc_workers


def _get_plugins_workers():
    # NOTE(twilson) get_plugins also returns the core plugin
    plugins = directory.get_unique_plugins()

    # TODO(twilson) Instead of defaulting here, come up with a good way to
    # share a common get_workers default between NeutronPluginBaseV2 and
    # ServicePluginBase
    return [
        plugin_worker
        for plugin in plugins if hasattr(plugin, 'get_workers')
        for plugin_worker in plugin.get_workers()
    ]


def _get_ovn_maintenance_worker():
    for worker in _get_plugins_workers():
        if isinstance(worker, ovn_worker.MaintenanceWorker):
            return worker


class AllServicesNeutronWorker(neutron_worker.NeutronBaseWorker):
    def __init__(self, services, worker_process_count=1):
        super().__init__(worker_process_count)
        self._services = services
        for srv in self._services:
            self._check_base_worker_service(srv)
        self._launcher = common_service.Launcher(cfg.CONF,
                                                 restart_method='mutate')

    def start(self):
        for srv in self._services:
            # Unset the 'set_proctitle' flag to prevent each service to
            # re-write the process title already defined and set by this class.
            srv.set_proctitle = 'off'
            self._launcher.launch_service(srv)
        super().start(desc="services worker")

    def stop(self):
        self._launcher.stop()

    def wait(self):
        self._launcher.wait()

    def reset(self):
        self._launcher.restart()

    @staticmethod
    def _check_base_worker_service(srv):
        if not isinstance(srv, base_worker.BaseWorker):
            raise TypeError(
                _('Service %(srv)s must an instance of %(base)s!)') %
                {'srv': srv, 'base': base_worker.BaseWorker})


def _start_workers(workers, neutron_api=None):
    process_workers = [
        plugin_worker for plugin_worker in workers
        if plugin_worker.worker_process_count > 0
    ]

    try:
        if process_workers:
            # Get eventual already existing instance from WSGI app
            worker_launcher = None
            if neutron_api:
                worker_launcher = neutron_api.wsgi_app.process_launcher
            if worker_launcher is None:
                worker_launcher = common_service.ProcessLauncher(
                    cfg.CONF, restart_method='mutate',
                )

            # add extra process worker and spawn there all workers with
            # worker_process_count == 0
            thread_workers = [
                plugin_worker for plugin_worker in workers
                if plugin_worker.worker_process_count < 1
            ]
            if thread_workers:
                process_workers.append(
                    AllServicesNeutronWorker(thread_workers)
                )

            # dispose the whole pool before os.fork, otherwise there will
            # be shared DB connections in child processes which may cause
            # DB errors.
            session.get_context_manager().dispose_pool()

            for worker in process_workers:
                worker_launcher.launch_service(worker,
                                               worker.worker_process_count)
        else:
            worker_launcher = common_service.ServiceLauncher(cfg.CONF)
            for worker in workers:
                worker_launcher.launch_service(worker)
        return worker_launcher
    except Exception:
        with excutils.save_and_reraise_exception():
            LOG.exception('Unrecoverable error: please check log for '
                          'details.')


def start_rpc_workers():
    rpc_workers = _get_rpc_workers()
    LOG.debug('Using launcher for rpc, workers=%s (configured rpc_workers=%s)',
              len(rpc_workers), cfg.CONF.rpc_workers)
    launcher = _start_workers(rpc_workers)
    registry.publish(resources.PROCESS, events.AFTER_SPAWN, None)
    return launcher


def start_periodic_workers():
    periodic_workers = _get_plugins_workers()
    thread_workers = [worker for worker in periodic_workers
                      if worker.worker_process_count < 1]
    launcher = _start_workers(thread_workers)
    registry.publish(resources.PROCESS, events.AFTER_SPAWN, None)
    return launcher


def start_plugins_workers():
    plugins_workers = _get_plugins_workers()
    return _start_workers(plugins_workers)


def start_ovn_maintenance_worker():
    ovn_maintenance_worker = _get_ovn_maintenance_worker()
    if not ovn_maintenance_worker:
        return

    return _start_workers([ovn_maintenance_worker])


def _get_api_workers():
    workers = cfg.CONF.api_workers
    if workers is None:
        workers = _get_worker_count()
    return workers


class Service(n_rpc.Service):
    """Service object for binaries running on hosts.

    A service takes a manager and enables rpc by listening to queues based
    on topic. It also periodically runs tasks on the manager.
    """

    def __init__(self, host, binary, topic, manager, *args,
                 report_interval=None, periodic_interval=None,
                 periodic_fuzzy_delay=None, **kwargs):

        self.binary = binary
        self.manager_class_name = manager
        manager_class = importutils.import_class(self.manager_class_name)
        self.manager = manager_class(host=host, *args, **kwargs)
        self.report_interval = report_interval
        self.periodic_interval = periodic_interval
        self.periodic_fuzzy_delay = periodic_fuzzy_delay
        self.saved_args, self.saved_kwargs = args, kwargs
        self.timers = []
        profiler.setup(binary, host)
        super().__init__(host, topic, manager=self.manager)

    def start(self):
        self.manager.init_host()
        super().start()
        if self.report_interval:
            pulse = loopingcall.FixedIntervalLoopingCall(f=self.report_state)
            pulse.start(interval=self.report_interval,
                        initial_delay=self.report_interval)
            self.timers.append(pulse)

        if self.periodic_interval:
            if self.periodic_fuzzy_delay:
                initial_delay = secrets.SystemRandom().randint(
                    0, self.periodic_fuzzy_delay)
            else:
                initial_delay = None

            periodic = loopingcall.FixedIntervalLoopingCall(
                f=self.periodic_tasks)
            periodic.start(interval=self.periodic_interval,
                           initial_delay=initial_delay)
            self.timers.append(periodic)
        self.manager.after_start()

    def __getattr__(self, key):
        manager = self.__dict__.get('manager', None)
        return getattr(manager, key)

    @classmethod
    def create(cls, host=None, binary=None, topic=None, manager=None,
               report_interval=None, periodic_interval=None,
               periodic_fuzzy_delay=None):
        """Instantiates class and passes back application object.

        :param host: defaults to cfg.CONF.host
        :param binary: defaults to basename of executable
        :param topic: defaults to bin_name - 'neutron-' part
        :param manager: defaults to cfg.CONF.<topic>_manager
        :param report_interval: defaults to cfg.CONF.report_interval
        :param periodic_interval: defaults to cfg.CONF.periodic_interval
        :param periodic_fuzzy_delay: defaults to cfg.CONF.periodic_fuzzy_delay

        """
        if not host:
            host = cfg.CONF.host
        if not binary:
            binary = os.path.basename(inspect.stack()[-1][1])
        if not topic:
            topic = binary.rpartition('neutron-')[2]
            topic = topic.replace("-", "_")
        if not manager:
            manager = cfg.CONF.get('%s_manager' % topic, None)
        if report_interval is None:
            report_interval = cfg.CONF.report_interval
        if periodic_interval is None:
            periodic_interval = cfg.CONF.periodic_interval
        if periodic_fuzzy_delay is None:
            periodic_fuzzy_delay = cfg.CONF.periodic_fuzzy_delay
        service_obj = cls(host, binary, topic, manager,
                          report_interval=report_interval,
                          periodic_interval=periodic_interval,
                          periodic_fuzzy_delay=periodic_fuzzy_delay)

        return service_obj

    def kill(self):
        """Destroy the service object."""
        self.stop()

    def stop(self):
        super().stop()
        for x in self.timers:
            try:
                x.stop()
            except Exception:
                LOG.exception("Exception occurs when timer stops")
        self.timers = []
        self.manager.stop()

    def wait(self):
        super().wait()
        for x in self.timers:
            try:
                x.wait()
            except Exception:
                LOG.exception("Exception occurs when waiting for timer")

    def reset(self):
        config.reset_service()

    def periodic_tasks(self, raise_on_error=False):
        """Tasks to be run at a periodic interval."""
        ctxt = context.get_admin_context()
        self.manager.periodic_tasks(ctxt, raise_on_error=raise_on_error)

    def report_state(self):
        """Update the state of this service."""
        # Todo(gongysh) report state to neutron server
        pass
