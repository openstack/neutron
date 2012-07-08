# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 Cisco Systems, Inc.  All rights reserved.
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
# @author: Sumit Naiksatam, Cisco Systems, Inc.
# @author: Rohit Agarwalla, Cisco Systems, Inc.

from quantum.openstack.common import cfg


vlan_opts = [
    cfg.IntOpt('vlan_start', default=1000),
    cfg.IntOpt('vlan_end', default=3000),
]

database_opts = [
    cfg.StrOpt('sql_connection', default='sqlite://'),
    cfg.IntOpt('reconnect_interval', default=2),
]

bridge_opts = [
    cfg.StrOpt('physical_interface', default='eth1'),
]

agent_opts = [
    cfg.IntOpt('polling_interval', default=2),
    cfg.StrOpt('root_helper', default='sudo'),
    cfg.BoolOpt('target_v2_api', default=False),
]


def parse(config_file):
    conf = cfg.CONF
    if 'config_file' in conf:
        conf.config_file.append(config_file)
    else:
        conf.config_file = [config_file]
    conf(args=[], default_config_files=conf.config_file)
    conf.register_opts(vlan_opts, "VLANS")
    conf.register_opts(database_opts, "DATABASE")
    conf.register_opts(bridge_opts, "LINUX_BRIDGE")
    conf.register_opts(agent_opts, "AGENT")
    return conf
