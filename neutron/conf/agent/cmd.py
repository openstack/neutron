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


ip_opts = [
    cfg.BoolOpt('allsets',
                default=False,
                help=_('Destroy all IPsets.')),
    cfg.BoolOpt('force',
                default=False,
                help=_('Destroy IPsets even if there is an iptables '
                       'reference.')),
    cfg.StrOpt('prefix',
               default='N',  # ipset_manager.NET_PREFIX
               help=_('String prefix used to match IPset names.')),
]

netns_opts = [
    cfg.BoolOpt('force',
                default=False,
                help=_('Delete the namespace by removing all devices.')),
    cfg.StrOpt('agent-type',
               choices=['dhcp', 'l3'],
               help=_('Cleanup resources of a specific agent type only.')),
]

ovs_opts = [
    cfg.BoolOpt('ovs_all_ports',
                default=False,
                help=_('True to delete all ports on all the OpenvSwitch '
                       'bridges. False to delete ports created by '
                       'Neutron on integration and external network '
                       'bridges.'))
]


def register_cmd_opts(opts, cfg=cfg.CONF):
    cfg.register_cli_opts(opts)
