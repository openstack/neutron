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
import threading

import httplib2
import netaddr
from oslo_config import cfg
from oslo_log import log as logging
from six.moves import queue

from neutron._i18n import _
from neutron.agent.l3 import ha
from neutron.agent.linux import daemon
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils as agent_utils
from neutron.common import config
from neutron.common import utils as common_utils
from neutron.conf.agent.l3 import keepalived
from neutron import privileged


LOG = logging.getLogger(__name__)
INITIAL_STATE_READ_TIMEOUT = 10


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
        self._initial_state = None
        super(MonitorDaemon, self).__init__(pidfile, uuid=router_id,
                                            user=user, group=group)

    @property
    def initial_state(self):
        return self._initial_state

    @initial_state.setter
    def initial_state(self, state):
        if not self._initial_state:
            LOG.debug('Initial status of router %s is %s', self.router_id,
                      state)
            self._initial_state = state

    def run(self):
        self._thread_initial_state = threading.Thread(
            target=self.handle_initial_state)
        self._thread_ip_monitor = threading.Thread(
            target=ip_lib.ip_monitor,
            args=(self.namespace, self.queue, self.event_stop,
                  self.event_started))
        self._thread_read_queue = threading.Thread(
            target=self.read_queue,
            args=(self.queue, self.event_stop, self.event_started))
        self._thread_initial_state.start()
        self._thread_ip_monitor.start()
        self._thread_read_queue.start()

        # NOTE(ralonsoh): if the initial status is not read in a defined
        # timeout, "backup" state is set.
        self._thread_initial_state.join(timeout=INITIAL_STATE_READ_TIMEOUT)
        if not self.initial_state:
            LOG.warning('Timeout reading the initial status of router %s, '
                        'state is set to "backup".', self.router_id)
            self.write_state_change('backup')
            self.notify_agent('backup')

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
                new_state = 'master' if event['event'] == 'added' else 'backup'
                self.write_state_change(new_state)
                self.notify_agent(new_state)
            elif event['name'] != self.interface and event['event'] == 'added':
                # Send GARPs for all new router interfaces.
                # REVISIT(jlibosva): keepalived versions 1.2.19 and below
                # contain bug where gratuitous ARPs are not sent on receiving
                # SIGHUP signal. This is a workaround to this bug. keepalived
                # has this issue fixed since 1.2.20 but the version is not
                # packaged in some distributions (RHEL/CentOS/Ubuntu Xenial).
                # Remove this code once new keepalived versions are available.
                self.send_garp(event)

    def handle_initial_state(self):
        try:
            state = 'backup'
            cidr = common_utils.ip_to_cidr(self.cidr)
            # NOTE(ralonsoh): "get_devices_with_ip" without passing an IP
            # address performs one single pyroute2 command. Because the number
            # of interfaces in the namespace is reduced, this is faster.
            for address in ip_lib.get_devices_with_ip(self.namespace):
                if (address['name'] == self.interface and
                        address['cidr'] == cidr):
                    state = 'master'
                    break

            if not self.initial_state:
                self.write_state_change(state)
                self.notify_agent(state)
        except Exception:
            if not self.initial_state:
                LOG.exception('Failed to get initial status of router %s',
                              self.router_id)

    def write_state_change(self, state):
        self.initial_state = state
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
                     'X-Neutron-State': state,
                     'Connection': 'close'},
            connection_type=KeepalivedUnixDomainConnection)

        if resp.status != 200:
            raise Exception(_('Unexpected response: %s') % resp)

        LOG.debug('Notified agent router %s, state %s', self.router_id, state)

    def send_garp(self, event):
        """Send gratuitous ARP for given event."""
        ip_address = str(netaddr.IPNetwork(event['cidr']).ip)
        ip_lib.send_ip_addr_adv_notif(
            self.namespace,
            event['name'],
            ip_address,
            log_exception=False,
            use_eventlet=False
        )
        LOG.debug('Sent GARP to %(ip_address)s from %(device_name)s',
                  {'ip_address': ip_address, 'device_name': event['name']})

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
