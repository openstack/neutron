# Copyright (c) 2015 Red Hat Inc.
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
import queue
import sys
import threading

import httplib2
from oslo_config import cfg
from oslo_log import log as logging

from neutron._i18n import _
from neutron.agent.l3 import ha
from neutron.agent.linux import daemon
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils as agent_utils
from neutron.common import config
from neutron.conf.agent.l3 import keepalived
from neutron import privileged


LOG = logging.getLogger(__name__)


class KeepalivedUnixDomainConnection(agent_utils.UnixDomainHTTPConnection):
    def __init__(self, *args, **kwargs):
        # Old style super initialization is required!
        agent_utils.UnixDomainHTTPConnection.__init__(
            self, *args, **kwargs)
        self.socket_path = (
            ha.L3AgentKeepalivedStateChangeServer.
            get_keepalived_state_change_socket_path(cfg.CONF))


class MonitorDaemon(daemon.Daemon):
    def __init__(self, pidfile, router_id, user, group, namespace, conf_dir,
                 interface, cidr):
        self.router_id = router_id
        self.namespace = namespace
        self.conf_dir = conf_dir
        self.interface = interface
        self.cidr = cidr
        self.monitor = None
        self.event_stop = threading.Event()
        self.event_started = threading.Event()
        self.queue = queue.Queue()
        super(MonitorDaemon, self).__init__(pidfile, uuid=router_id,
                                            user=user, group=group)

    def run(self):
        self._thread_ip_monitor = threading.Thread(
            target=ip_lib.ip_monitor,
            args=(self.namespace, self.queue, self.event_stop,
                  self.event_started))
        self._thread_read_queue = threading.Thread(
            target=self.read_queue,
            args=(self.queue, self.event_stop, self.event_started))
        self._thread_ip_monitor.start()
        self._thread_read_queue.start()
        self.handle_initial_state()
        self._thread_read_queue.join()

    def read_queue(self, _queue, event_stop, event_started):
        event_started.wait()
        while not event_stop.is_set():
            try:
                event = _queue.get(timeout=2)
            except queue.Empty:
                event = None
            if not event:
                continue

            if event['name'] == self.interface and event['cidr'] == self.cidr:
                if event['event'] == 'added':
                    new_state = 'primary'
                else:
                    new_state = 'backup'
                self.write_state_change(new_state)
                self.notify_agent(new_state)

    def handle_initial_state(self):
        try:
            state = 'backup'
            ip = ip_lib.IPDevice(self.interface, self.namespace)
            for address in ip.addr.list():
                if address.get('cidr') == self.cidr:
                    state = 'primary'
                    break

            LOG.debug('Initial status of router %s is %s',
                      self.router_id, state)
            self.write_state_change(state)
            self.notify_agent(state)
        except Exception:
            LOG.exception('Failed to get initial status of router %s',
                          self.router_id)

    def write_state_change(self, state):
        with open(os.path.join(
                self.conf_dir, 'state'), 'w') as state_file:
            state_file.write(state)
        LOG.debug('Wrote router %s state %s', self.router_id, state)

    def notify_agent(self, state):
        resp, content = httplib2.Http().request(
            # Note that the message is sent via a Unix domain socket so that
            # the URL doesn't matter.
            'http://127.0.0.1/',
            headers={'X-Neutron-Router-Id': self.router_id,
                     'X-Neutron-State': state},
            connection_type=KeepalivedUnixDomainConnection)

        if resp.status != 200:
            raise Exception(_('Unexpected response: %s') % resp)

        LOG.debug('Notified agent router %s, state %s', self.router_id, state)

    def handle_sigterm(self, signum, frame):
        self.event_stop.set()
        self._thread_read_queue.join(timeout=5)
        super(MonitorDaemon, self).handle_sigterm(signum, frame)


def configure(conf):
    config.init(sys.argv[1:])
    conf.set_override('log_dir', cfg.CONF.conf_dir)
    conf.set_override('debug', True)
    conf.set_override('use_syslog', True)
    config.setup_logging()
    privileged.default.set_client_mode(False)


def main():
    keepalived.register_cli_l3_agent_keepalived_opts()
    keepalived.register_l3_agent_keepalived_opts()
    configure(cfg.CONF)
    MonitorDaemon(cfg.CONF.pid_file,
                  cfg.CONF.router_id,
                  cfg.CONF.user,
                  cfg.CONF.group,
                  cfg.CONF.namespace,
                  cfg.CONF.conf_dir,
                  cfg.CONF.monitor_interface,
                  cfg.CONF.monitor_cidr).start()
