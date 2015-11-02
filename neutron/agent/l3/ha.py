# Copyright (c) 2014 OpenStack Foundation.
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

import os

import eventlet
from oslo_config import cfg
from oslo_log import log as logging
import webob

from neutron.agent.linux import keepalived
from neutron.agent.linux import utils as agent_utils
from neutron.i18n import _LI
from neutron.notifiers import batch_notifier

LOG = logging.getLogger(__name__)

HA_DEV_PREFIX = 'ha-'
KEEPALIVED_STATE_CHANGE_SERVER_BACKLOG = 4096

OPTS = [
    cfg.StrOpt('ha_confs_path',
               default='$state_path/ha_confs',
               help=_('Location to store keepalived/conntrackd '
                      'config files')),
    cfg.StrOpt('ha_vrrp_auth_type',
               default='PASS',
               choices=keepalived.VALID_AUTH_TYPES,
               help=_('VRRP authentication type')),
    cfg.StrOpt('ha_vrrp_auth_password',
               help=_('VRRP authentication password'),
               secret=True),
    cfg.IntOpt('ha_vrrp_advert_int',
               default=2,
               help=_('The advertisement interval in seconds')),
]


class KeepalivedStateChangeHandler(object):
    def __init__(self, agent):
        self.agent = agent

    @webob.dec.wsgify(RequestClass=webob.Request)
    def __call__(self, req):
        router_id = req.headers['X-Neutron-Router-Id']
        state = req.headers['X-Neutron-State']
        self.enqueue(router_id, state)

    def enqueue(self, router_id, state):
        LOG.debug('Handling notification for router '
                  '%(router_id)s, state %(state)s', {'router_id': router_id,
                                                     'state': state})
        self.agent.enqueue_state_change(router_id, state)


class L3AgentKeepalivedStateChangeServer(object):
    def __init__(self, agent, conf):
        self.agent = agent
        self.conf = conf

        agent_utils.ensure_directory_exists_without_file(
            self.get_keepalived_state_change_socket_path(self.conf))

    @classmethod
    def get_keepalived_state_change_socket_path(cls, conf):
        return os.path.join(conf.state_path, 'keepalived-state-change')

    def run(self):
        server = agent_utils.UnixDomainWSGIServer(
            'neutron-keepalived-state-change')
        server.start(KeepalivedStateChangeHandler(self.agent),
                     self.get_keepalived_state_change_socket_path(self.conf),
                     workers=0,
                     backlog=KEEPALIVED_STATE_CHANGE_SERVER_BACKLOG)
        server.wait()


class AgentMixin(object):
    def __init__(self, host):
        self._init_ha_conf_path()
        super(AgentMixin, self).__init__(host)
        self.state_change_notifier = batch_notifier.BatchNotifier(
            self._calculate_batch_duration(), self.notify_server)
        eventlet.spawn(self._start_keepalived_notifications_server)

    def _start_keepalived_notifications_server(self):
        state_change_server = (
            L3AgentKeepalivedStateChangeServer(self, self.conf))
        state_change_server.run()

    def _calculate_batch_duration(self):
        # Slave becomes the master after not hearing from it 3 times
        detection_time = self.conf.ha_vrrp_advert_int * 3

        # Keepalived takes a couple of seconds to configure the VIPs
        configuration_time = 2

        # Give it enough slack to batch all events due to the same failure
        return (detection_time + configuration_time) * 2

    def enqueue_state_change(self, router_id, state):
        LOG.info(_LI('Router %(router_id)s transitioned to %(state)s'),
                 {'router_id': router_id,
                  'state': state})

        try:
            ri = self.router_info[router_id]
        except KeyError:
            LOG.info(_LI('Router %s is not managed by this agent. It was '
                         'possibly deleted concurrently.'), router_id)
            return

        self._configure_ipv6_ra_on_ext_gw_port_if_necessary(ri, state)
        if self.conf.enable_metadata_proxy:
            self._update_metadata_proxy(ri, router_id, state)
        self._update_radvd_daemon(ri, state)
        self.state_change_notifier.queue_event((router_id, state))

    def _configure_ipv6_ra_on_ext_gw_port_if_necessary(self, ri, state):
        # If ipv6 is enabled on the platform, ipv6_gateway config flag is
        # not set and external_network associated to the router does not
        # include any IPv6 subnet, enable the gateway interface to accept
        # Router Advts from upstream router for default route.
        ex_gw_port_id = ri.ex_gw_port and ri.ex_gw_port['id']
        if state == 'master' and ex_gw_port_id and ri.use_ipv6:
            gateway_ips = ri._get_external_gw_ips(ri.ex_gw_port)
            if not ri.is_v6_gateway_set(gateway_ips):
                interface_name = ri.get_external_device_name(ex_gw_port_id)
                ri.driver.configure_ipv6_ra(ri.ns_name, interface_name)

    def _update_metadata_proxy(self, ri, router_id, state):
        if state == 'master':
            LOG.debug('Spawning metadata proxy for router %s', router_id)
            self.metadata_driver.spawn_monitored_metadata_proxy(
                self.process_monitor, ri.ns_name, self.conf.metadata_port,
                self.conf, router_id=ri.router_id)
        else:
            LOG.debug('Closing metadata proxy for router %s', router_id)
            self.metadata_driver.destroy_monitored_metadata_proxy(
                self.process_monitor, ri.router_id, ri.ns_name, self.conf)

    def _update_radvd_daemon(self, ri, state):
        # Radvd has to be spawned only on the Master HA Router. If there are
        # any state transitions, we enable/disable radvd accordingly.
        if state == 'master':
            ri.enable_radvd()
        else:
            ri.disable_radvd()

    def notify_server(self, batched_events):
        translation_map = {'master': 'active',
                           'backup': 'standby',
                           'fault': 'standby'}
        translated_states = dict((router_id, translation_map[state]) for
                                 router_id, state in batched_events)
        LOG.debug('Updating server with HA routers states %s',
                  translated_states)
        self.plugin_rpc.update_ha_routers_states(
            self.context, translated_states)

    def _init_ha_conf_path(self):
        ha_full_path = os.path.dirname("/%s/" % self.conf.ha_confs_path)
        agent_utils.ensure_dir(ha_full_path)
