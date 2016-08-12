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
import sys

import httplib2
from oslo_config import cfg
from oslo_log import log as logging
import requests

from neutron._i18n import _, _LE
from neutron.agent.l3 import ha
from neutron.agent.linux import daemon
from neutron.agent.linux import ip_monitor
from neutron.agent.linux import utils as agent_utils
from neutron.common import config
from neutron.conf.agent.l3 import keepalived


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
        super(MonitorDaemon, self).__init__(pidfile, uuid=router_id,
                                            user=user, group=group)

    def run(self, run_as_root=False):
        monitor = ip_monitor.IPMonitor(namespace=self.namespace,
                                       run_as_root=run_as_root)
        monitor.start()
        # Only drop privileges if the process is currently running as root
        # (The run_as_root variable name here is unfortunate - It means to
        # use a root helper when the running process is NOT already running
        # as root
        if not run_as_root:
            super(MonitorDaemon, self).run()
        for iterable in monitor:
            self.parse_and_handle_event(iterable)

    def parse_and_handle_event(self, iterable):
        try:
            event = ip_monitor.IPMonitorEvent.from_text(iterable)
            if event.interface == self.interface and event.cidr == self.cidr:
                new_state = 'master' if event.added else 'backup'
                self.write_state_change(new_state)
                self.notify_agent(new_state)
        except Exception:
            LOG.exception(_LE(
                'Failed to process or handle event for line %s'), iterable)

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

        if resp.status != requests.codes.ok:
            raise Exception(_('Unexpected response: %s') % resp)

        LOG.debug('Notified agent router %s, state %s', self.router_id, state)


def configure(conf):
    config.init(sys.argv[1:])
    conf.set_override('log_dir', cfg.CONF.conf_dir)
    conf.set_override('debug', True)
    config.setup_logging()


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
