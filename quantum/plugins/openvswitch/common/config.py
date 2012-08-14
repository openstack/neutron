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


# Topic for tunnel notifications between the plugin and agent
TUNNEL = 'tunnel'

database_opts = [
    cfg.StrOpt('sql_connection', default='sqlite://'),
    cfg.IntOpt('sql_max_retries', default=-1),
    cfg.IntOpt('reconnect_interval', default=2),
]

ovs_opts = [
    cfg.BoolOpt('enable_tunneling', default=False),
    cfg.StrOpt('integration_bridge', default='br-int'),
    cfg.StrOpt('tunnel_bridge', default='br-tun'),
    cfg.StrOpt('local_ip', default='10.0.0.3'),
    cfg.IntOpt('vlan_min', default=1),
    cfg.IntOpt('vlan_max', default=4094),
]

agent_opts = [
    cfg.IntOpt('polling_interval', default=2),
    cfg.StrOpt('root_helper', default='sudo'),
    cfg.StrOpt('log_file', default=None),
    cfg.BoolOpt('rpc', default=True),
]


cfg.CONF.register_opts(database_opts, "DATABASE")
cfg.CONF.register_opts(ovs_opts, "OVS")
cfg.CONF.register_opts(agent_opts, "AGENT")
