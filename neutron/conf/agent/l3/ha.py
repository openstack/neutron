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

from oslo_config import cfg

from neutron._i18n import _
from neutron.agent.linux import keepalived
from neutron.common import utils as common_utils


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
    cfg.IntOpt('ha_keepalived_state_change_server_threads',
               default=(1 + common_utils.cpu_count()) // 2,
               sample_default='(1 + <num_of_cpus>) / 2',
               min=1,
               help=_('Number of concurrent threads for '
                      'keepalived server connection requests. '
                      'More threads create a higher CPU load '
                      'on the agent node.')),
]


def register_l3_agent_ha_opts(cfg=cfg.CONF):
    cfg.register_opts(OPTS)
