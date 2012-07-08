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
    cfg.IntOpt('reconnect_interval', default=2),
]

ovs_opts = [
    cfg.StrOpt('integration_bridge', default='br-int'),
    cfg.StrOpt('openflow_controller', default='127.0.0.1:6633'),
    cfg.StrOpt('openflow_rest_api', default='127.0.0.1:8080'),
]

agent_opts = [
    cfg.IntOpt('polling_interval', default=2),
    cfg.StrOpt('root_helper', default='sudo'),
]


def parse(config_file):
    conf = cfg.CONF
    if 'config_file' in conf:
        conf.config_file.append(config_file)
    else:
        conf.config_file = [config_file]
    conf(args=[], default_config_files=conf.config_file)
    conf.register_opts(database_opts, "DATABASE")
    conf.register_opts(ovs_opts, "OVS")
    conf.register_opts(agent_opts, "AGENT")
    return conf
