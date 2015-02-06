# Copyright 2012, Nachi Ueno, NTT MCL, Inc.
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


meta_plugin_opts = [
    cfg.StrOpt(
        'plugin_list',
        default='',
        help=_("Comma separated list of flavor:neutron_plugin for "
               "plugins to load. Extension method is searched in the "
               "list order and the first one is used.")),
    cfg.StrOpt(
        'l3_plugin_list',
        default='',
        help=_("Comma separated list of flavor:neutron_plugin for L3 "
               "service plugins to load. This is intended for specifying "
               "L2 plugins which support L3 functions. If you use a router "
               "service plugin, set this blank.")),
    cfg.StrOpt(
        'default_flavor',
        default='',
        help=_("Default flavor to use, when flavor:network is not "
               "specified at network creation.")),
    cfg.StrOpt(
        'default_l3_flavor',
        default='',
        help=_("Default L3 flavor to use, when flavor:router is not "
               "specified at router creation. Ignored if 'l3_plugin_list' "
               "is blank.")),
    cfg.StrOpt(
        'supported_extension_aliases',
        default='',
        help=_("Comma separated list of supported extension aliases.")),
    cfg.StrOpt(
        'extension_map',
        default='',
        help=_("Comma separated list of method:flavor to select specific "
               "plugin for a method. This has priority over method search "
               "order based on 'plugin_list'.")),
    cfg.StrOpt(
        'rpc_flavor',
        default='',
        help=_("Specifies flavor for plugin to handle 'q-plugin' RPC "
               "requests.")),
]

proxy_plugin_opts = [
    cfg.StrOpt('admin_user',
               help=_("Admin user")),
    cfg.StrOpt('admin_password',
               help=_("Admin password"),
               secret=True),
    cfg.StrOpt('admin_tenant_name',
               help=_("Admin tenant name")),
    cfg.StrOpt('auth_url',
               help=_("Authentication URL")),
    cfg.StrOpt('auth_strategy', default='keystone',
               help=_("The type of authentication to use")),
    cfg.StrOpt('auth_region',
               help=_("Authentication region")),
]

cfg.CONF.register_opts(meta_plugin_opts, "META")
cfg.CONF.register_opts(proxy_plugin_opts, "PROXY")
