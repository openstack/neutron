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
import signal
import sys

import httplib2
import netaddr
from oslo_config import cfg
from oslo_log import log as logging

from neutron._i18n import _
from neutron.agent.l3 import ha
from neutron.agent.linux import daemon
from neutron.agent.linux import ip_lib
from neutron.agent.linux import ip_monitor
from neutron.agent.linux import utils as agent_utils
from neutron.common import config
from neutron.conf.agent import common as agent_config
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
        self.monitor = None
        super(MonitorDaemon, self).__init__(pidfile, uuid=router_id,
                                            user=user, group=group)

    def run(self, run_as_root=False):
        self.monitor = ip_monitor.IPMonitor(namespace=self.namespace,
                                            run_as_root=run_as_root)
        self.monitor.start()
        # Only drop privileges if the process is currently running as root
        # (The run_as_root variable name here is unfortunate - It means to
        # use a root helper when the running process is NOT already running
        # as root
        if not run_as_root:
            super(MonitorDaemon, self).run()
        self.handle_initial_state()
        for iterable in self.monitor:
            self.parse_and_handle_event(iterable)

    def parse_and_handle_event(self, iterable):
        try:
            event = ip_monitor.IPMonitorEvent.from_text(iterable)
            if event.interface == self.interface and event.cidr == self.cidr:
                new_state = 'master' if event.added else 'backup'
                self.write_state_change(new_state)
                self.notify_agent(new_state)
            elif event.interface != self.interface and event.added:
                # Send GARPs for all new router interfaces.
                # REVISIT(jlibosva): keepalived versions 1.2.19 and below
                # contain bug where gratuitous ARPs are not sent on receiving
                # SIGHUP signal. This is a workaround to this bug. keepalived
                # has this issue fixed since 1.2.20 but the version is not
                # packaged in some distributions (RHEL/CentOS/Ubuntu Xenial).
                # Remove this code once new keepalived versions are available.
                self.send_garp(event)
        except Exception:
            LOG.exception('Failed to process or handle event for line %s',
                          iterable)

    def handle_initial_state(self):
        try:
            state = 'backup'
            ip = ip_lib.IPDevice(self.interface, self.namespace)
            for address in ip.addr.list():
                if address.get('cidr') == self.cidr:
                    state = 'master'
                    self.write_state_change(state)
                    self.notify_agent(state)
                    break

            LOG.debug('Initial status of router %s is %s',
                      self.router_id, state)
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

    def send_garp(self, event):
        """Send gratuitous ARP for given event."""
        ip_lib.send_ip_addr_adv_notif(
            self.namespace,
            event.interface,
            str(netaddr.IPNetwork(event.cidr).ip),
            log_exception=False
        )

    def _kill_monitor(self):
        if self.monitor:
            # Kill PID instead of calling self.monitor.stop() because the ip
            # monitor is running as root while keepalived-state-change is not
            # (dropped privileges after launching the ip monitor) and will fail
            # with "Permission denied". Also, we can safely do this because the
            # monitor was launched with respawn_interval=None so it won't be
            # automatically respawned
            agent_utils.kill_process(self.monitor.pid, signal.SIGKILL,
                                     run_as_root=True)

    def handle_sigterm(self, signum, frame):
        self._kill_monitor()
        super(MonitorDaemon, self).handle_sigterm(signum, frame)


def configure(conf):
    config.init(sys.argv[1:])
    conf.set_override('log_dir', cfg.CONF.conf_dir)
    conf.set_override('debug', True)
    conf.set_override('use_syslog', True)
    config.setup_logging()
    agent_config.setup_privsep()


def main():
    agent_config.register_root_helper(cfg.CONF)
    cfg.CONF.register_cli_opts(agent_config.ROOT_HELPER_OPTS, 'AGENT')
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
