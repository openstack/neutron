# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2014 Big Switch Networks, Inc.
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
#
# @author: Mandeep Dhami, Big Switch Networks, Inc.
# @author: Sumit Naiksatam, sumitnaiksatam@gmail.com, Big Switch Networks, Inc.
# @author: Kevin Benton, Big Switch Networks, Inc.

"""
This module manages configuration options
"""

from oslo.config import cfg

from neutron.common import utils
from neutron.extensions import portbindings

restproxy_opts = [
    cfg.ListOpt('servers', default=['localhost:8800'],
                help=_("A comma separated list of BigSwitch or Floodlight "
                       "servers and port numbers. The plugin proxies the "
                       "requests to the BigSwitch/Floodlight server, "
                       "which performs the networking configuration. Only one"
                       "server is needed per deployment, but you may wish to"
                       "deploy multiple servers to support failover.")),
    cfg.StrOpt('server_auth', default=None, secret=True,
               help=_("The username and password for authenticating against "
                      " the BigSwitch or Floodlight controller.")),
    cfg.BoolOpt('server_ssl', default=False,
                help=_("If True, Use SSL when connecting to the BigSwitch or "
                       "Floodlight controller.")),
    cfg.BoolOpt('sync_data', default=False,
                help=_("Sync data on connect")),
    cfg.IntOpt('server_timeout', default=10,
               help=_("Maximum number of seconds to wait for proxy request "
                      "to connect and complete.")),
    cfg.StrOpt('neutron_id', default='neutron-' + utils.get_hostname(),
               deprecated_name='quantum_id',
               help=_("User defined identifier for this Neutron deployment")),
    cfg.BoolOpt('add_meta_server_route', default=True,
                help=_("Flag to decide if a route to the metadata server "
                       "should be injected into the VM")),
]
router_opts = [
    cfg.MultiStrOpt('tenant_default_router_rule', default=['*:any:any:permit'],
                    help=_("The default router rules installed in new tenant "
                           "routers. Repeat the config option for each rule. "
                           "Format is <tenant>:<source>:<destination>:<action>"
                           " Use an * to specify default for all tenants.")),
    cfg.IntOpt('max_router_rules', default=200,
               help=_("Maximum number of router rules")),
]
nova_opts = [
    cfg.StrOpt('vif_type', default='ovs',
               help=_("Virtual interface type to configure on "
                      "Nova compute nodes")),
]

# Each VIF Type can have a list of nova host IDs that are fixed to that type
for i in portbindings.VIF_TYPES:
    opt = cfg.ListOpt('node_override_vif_' + i, default=[],
                      help=_("Nova compute nodes to manually set VIF "
                             "type to %s") % i)
    nova_opts.append(opt)

# Add the vif types for reference later
nova_opts.append(cfg.ListOpt('vif_types',
                             default=portbindings.VIF_TYPES,
                             help=_('List of allowed vif_type values.')))


def register_config():
    cfg.CONF.register_opts(restproxy_opts, "RESTPROXY")
    cfg.CONF.register_opts(router_opts, "ROUTER")
    cfg.CONF.register_opts(nova_opts, "NOVA")
