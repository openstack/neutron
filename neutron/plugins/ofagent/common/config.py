# Copyright (C) 2014 VA Linux Systems Japan K.K.
# Copyright (C) 2014 Fumihiko Kakuma <kakuma at valinux co jp>
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

from neutron.agent.common import config
from neutron.plugins.openvswitch.common import config as ovs_config


agent_opts = [
    cfg.IntOpt('get_datapath_retry_times', default=60,
               help=_("Number of seconds to retry acquiring "
                      "an Open vSwitch datapath")),
    cfg.ListOpt('physical_interface_mappings',
                default=[],
                help=_("List of <physical_network>:<physical_interface>")),
]


cfg.CONF.register_opts(ovs_config.ovs_opts, 'OVS')
cfg.CONF.register_opts(ovs_config.agent_opts, 'AGENT')
cfg.CONF.register_opts(agent_opts, 'AGENT')
config.register_agent_state_opts_helper(cfg.CONF)
config.register_root_helper(cfg.CONF)
