# Copyright 2015 OpenStack Foundation.
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

from networking_brocade.vyatta.vrouter import neutron_plugin as vrouter_plugin
from oslo_config import cfg

from neutron.common import constants as l3_constants

vrouter_opts = [
    cfg.StrOpt('tenant_admin_name', help=_('Name of tenant admin user.')),
    cfg.StrOpt('tenant_admin_password', secret=True,
               help=_('Tenant admin password.')),
    cfg.StrOpt('tenant_id',
               help=_('UUID of tenant that holds Vyatta vRouter instances.')),
    cfg.StrOpt('image_id',
               help=_('Nova image id for instances of Vyatta vRouter.')),
    cfg.StrOpt('flavor', default=2,
               help=_('Nova VM flavor for instances of Vyatta vRouter.')),
    cfg.StrOpt('management_network_id',
               help=_('Vyatta vRouter management network id.')),
    cfg.StrOpt('vrouter_credentials', default="vyatta:vyatta",
               help=_('Vyatta vRouter login credentials')),
    cfg.IntOpt('nova_poll_interval', default=5,
               help=_('Number of seconds between consecutive Nova queries '
                      'when waiting for router instance status change.')),
    cfg.IntOpt('nova_spawn_timeout', default=300,
               help=_('Number of seconds to wait for Nova to activate '
                      'instance before setting resource to error state.')),
    cfg.IntOpt('vrouter_poll_interval', default=5,
               help=_('Number of seconds between consecutive Vyatta vRouter '
                      'queries when waiting for router instance boot.')),
    cfg.IntOpt('vrouter_boot_timeout', default=300,
               help=_('Number of seconds to wait for Vyatta vRouter to boot '
                      'before setting resource to error state.')),
    cfg.StrOpt('keystone_url', help=_('Keystone URL.'))
]

cfg.CONF.register_opts(vrouter_opts, "VROUTER")


class VyattaVRouterPlugin(vrouter_plugin.VyattaVRouterMixin):
    """Brocade Neutron L3 Plugin for Vyatta vRouter.

    Supports CRUD operations on vRouter, add/remove interfaces from vRouter
    and floating IPs for VMs.It performs vRouter VM lifecyle management by
    calling Nova APIs during the Create and Delete Router calls.
    Once the vRouter VM is up, L3 plugin uses REST API to perform the
    configurations. L3 plugin supports add/remove router interfaces by
    attaching the neutron ports to vRouter VM using Nova API.
    RPC notifications will be used by the firewall agent that is coupled
    with l3-agent. This is needed for our firewall plugin.
    """

    supported_extension_aliases = [
        "router", "ext-gw-mode", "extraroute",
        l3_constants.L3_AGENT_SCHEDULER_EXT_ALIAS]

    def __init__(self):
        super(VyattaVRouterPlugin, self).__init__()
