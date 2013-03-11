# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Mellanox Technologies, Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from oslo.config import cfg

from quantum.agent.common import config
from quantum.plugins.mlnx.common import constants

DEFAULT_VLAN_RANGES = ['default:1:1000']
DEFAULT_INTERFACE_MAPPINGS = []

vlan_opts = [
    cfg.StrOpt('tenant_network_type', default='vlan',
               help=_("Network type for tenant networks "
               "(local, ib, vlan, or none)")),
    cfg.ListOpt('network_vlan_ranges',
                default=DEFAULT_VLAN_RANGES,
                help=_("List of <physical_network>:<vlan_min>:<vlan_max> "
                       "or <physical_network>")),
]


eswitch_opts = [
    cfg.ListOpt('physical_interface_mappings',
                default=DEFAULT_INTERFACE_MAPPINGS,
                help=_("List of <physical_network>:<physical_interface>")),
    cfg.StrOpt('vnic_type',
               default=constants.VIF_TYPE_DIRECT,
               help=_("type of VM network interface: direct or hosdev")),
    cfg.StrOpt('daemon_endpoint',
               default='tcp://127.0.0.1:5001',
               help=_('eswitch daemon end point')),
    cfg.IntOpt('request_timeout', default=3000,
               help=_("The number of milliseconds the agent will wait for "
                      "response on request to daemon.")),
]

agent_opts = [
    cfg.IntOpt('polling_interval', default=2,
               help=_("The number of seconds the agent will wait between "
                      "polling for local device changes.")),
]


cfg.CONF.register_opts(vlan_opts, "MLNX")
cfg.CONF.register_opts(eswitch_opts, "ESWITCH")
cfg.CONF.register_opts(agent_opts, "AGENT")
config.register_agent_state_opts_helper(cfg.CONF)
config.register_root_helper(cfg.CONF)
