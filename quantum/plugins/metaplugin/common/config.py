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

from quantum.openstack.common import cfg


database_opts = [
    cfg.StrOpt('sql_connection', default='sqlite://'),
    cfg.IntOpt('sql_max_retries', default=-1),
    cfg.IntOpt('reconnect_interval', default=2),
]

meta_plugin_opts = [
    cfg.StrOpt('plugin_list', default=''),
    cfg.StrOpt('l3_plugin_list', default=''),
    cfg.StrOpt('default_flavor', default=''),
    cfg.StrOpt('default_l3_flavor', default=''),
    cfg.StrOpt('supported_extension_aliases', default=''),
    cfg.StrOpt('extension_map', default='')
]

proxy_plugin_opts = [
    cfg.StrOpt('admin_user'),
    cfg.StrOpt('admin_password'),
    cfg.StrOpt('admin_tenant_name'),
    cfg.StrOpt('auth_url'),
    cfg.StrOpt('auth_strategy', default='keystone'),
    cfg.StrOpt('auth_region'),
]

cfg.CONF.register_opts(database_opts, "DATABASE")
cfg.CONF.register_opts(meta_plugin_opts, "META")
cfg.CONF.register_opts(proxy_plugin_opts, "PROXY")
