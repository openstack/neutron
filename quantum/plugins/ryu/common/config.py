# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Red Hat, Inc.
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
    cfg.IntOpt('sql_min_pool_size',
               default=1,
               help="Minimum number of SQL connections to keep open in a "
                    "pool"),
    cfg.IntOpt('sql_max_pool_size',
               default=5,
               help="Maximum number of SQL connections to keep open in a "
                    "pool"),
    cfg.IntOpt('sql_idle_timeout',
               default=3600,
               help="Timeout in seconds before idle sql connections are "
                    "reaped"),
    cfg.BoolOpt('sql_dbpool_enable',
                default=False,
                help="Enable the use of eventlet's db_pool for MySQL"),
]

ovs_opts = [
    cfg.StrOpt('integration_bridge', default='br-int'),
    cfg.StrOpt('openflow_controller', default='127.0.0.1:6633'),
    cfg.StrOpt('openflow_rest_api', default='127.0.0.1:8080'),
    cfg.IntOpt('tunnel_key_min', default=1),
    cfg.IntOpt('tunnel_key_max', default=0xffffff),
    cfg.StrOpt('tunnel_ip', default=None),
    cfg.StrOpt('tunnel_interface', default=None),
    cfg.IntOpt('ovsdb_port', default=6634),
    cfg.StrOpt('ovsdb_ip', default=None),
    cfg.StrOpt('ovsdb_interface', default=None),
]

agent_opts = [
    cfg.IntOpt('polling_interval', default=2),
    cfg.StrOpt('root_helper', default='sudo'),
]


cfg.CONF.register_opts(database_opts, "DATABASE")
cfg.CONF.register_opts(ovs_opts, "OVS")
cfg.CONF.register_opts(agent_opts, "AGENT")
