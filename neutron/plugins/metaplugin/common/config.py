# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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

from oslo.config import cfg


meta_plugin_opts = [
    cfg.StrOpt('plugin_list', default='',
               help=_("List of plugins to load")),
    cfg.StrOpt('l3_plugin_list', default='',
               help=_("List of L3 plugins to load")),
    cfg.StrOpt('default_flavor', default='',
               help=_("Default flavor to use")),
    cfg.StrOpt('default_l3_flavor', default='',
               help=_("Default L3 flavor to use")),
    cfg.StrOpt('supported_extension_aliases', default='',
               help=_("Supported extension aliases")),
    cfg.StrOpt('extension_map', default='',
               help=_("A list of extensions, per plugin, to load.")),
    cfg.StrOpt('rpc_flavor', default='',
               help=_("Flavor of which plugin handles RPC")),
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
