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


from neutron_lib import constants as n_const
from oslo_config import cfg

from neutron._i18n import _


L3_HA_OPTS = [
    cfg.BoolOpt('l3_ha',
                default=False,
                help=_('Enable HA mode for virtual routers.')),
    cfg.IntOpt('max_l3_agents_per_router',
               default=3,
               help=_("Maximum number of L3 agents which a HA router will be "
                      "scheduled on. If it is set to 0 then the router will "
                      "be scheduled on every agent.")),
    cfg.StrOpt('l3_ha_net_cidr',
               default=n_const.L3_HA_NET_CIDR,
               help=_('Subnet used for the L3 HA admin network.')),
    cfg.StrOpt('l3_ha_network_type', default='',
               help=_("The network type to use when creating the L3 HA "
                      "network for an HA router. By default, or if empty, the "
                      "first 'tenant_network_types' value is used. This is "
                      "helpful when the VRRP traffic should use a specific "
                      "network which is not the default one.")),
    cfg.StrOpt('l3_ha_network_physical_name', default='',
               help=_("The physical network name with which the L3 HA network "
                      "should be created."))
]


def register_db_l3_hamode_opts(conf=cfg.CONF):
    conf.register_opts(L3_HA_OPTS)
