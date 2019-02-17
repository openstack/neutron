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

from neutron_lib.utils import host
from oslo_config import cfg

from neutron._i18n import _
from neutron.agent.linux import keepalived


OPTS = [
    cfg.StrOpt('ha_confs_path',
               default='$state_path/ha_confs',
               help=_('Location to store keepalived config files')),
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
    cfg.IntOpt('ha_keepalived_state_change_server_threads',
               default=(1 + host.cpu_count()) // 2,
               sample_default='(1 + <num_of_cpus>) / 2',
               min=1,
               help=_('Number of concurrent threads for '
                      'keepalived server connection requests. '
                      'More threads create a higher CPU load '
                      'on the agent node.')),
    cfg.IntOpt('ha_vrrp_health_check_interval',
               default=0,
               help=_('The VRRP health check interval in seconds. Values > 0 '
                      'enable VRRP health checks. Setting it to 0 disables '
                      'VRRP health checks. Recommended value is 5. '
                      'This will cause pings to be sent to the gateway '
                      'IP address(es) - requires ICMP_ECHO_REQUEST '
                      'to be enabled on the gateway. '
                      'If gateway fails, all routers will be reported '
                      'as master, and master election will be repeated '
                      'in round-robin fashion, until one of the router '
                      'restore the gateway connection.')),
]


def register_l3_agent_ha_opts(cfg=cfg.CONF):
    cfg.register_opts(OPTS)
