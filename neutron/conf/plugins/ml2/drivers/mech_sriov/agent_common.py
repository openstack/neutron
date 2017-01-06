# Copyright 2014 Mellanox Technologies, Ltd
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


from oslo_config import cfg

from neutron._i18n import _

DEFAULT_DEVICE_MAPPINGS = []
DEFAULT_EXCLUDE_DEVICES = []

agent_opts = [
    cfg.IntOpt('polling_interval', default=2,
               help=_("The number of seconds the agent will wait between "
                      "polling for local device changes.")),
]

sriov_nic_opts = [
    cfg.ListOpt('physical_device_mappings',
                default=DEFAULT_DEVICE_MAPPINGS,
                help=_("Comma-separated list of "
                       "<physical_network>:<network_device> tuples mapping "
                       "physical network names to the agent's node-specific "
                       "physical network device interfaces of SR-IOV physical "
                       "function to be used for VLAN networks. All physical "
                       "networks listed in network_vlan_ranges on the server "
                       "should have mappings to appropriate interfaces on "
                       "each agent.")),
    cfg.ListOpt('exclude_devices',
                default=DEFAULT_EXCLUDE_DEVICES,
                help=_("Comma-separated list of "
                       "<network_device>:<vfs_to_exclude> tuples, mapping "
                       "network_device to the agent's node-specific list of "
                       "virtual functions that should not be used for virtual "
                       "networking. vfs_to_exclude is a semicolon-separated "
                       "list of virtual functions to exclude from "
                       "network_device. The network_device in the mapping "
                       "should appear in the physical_device_mappings "
                       "list.")),
]


def register_agent_sriov_nic_opts(cfg=cfg.CONF):
    cfg.register_opts(agent_opts, 'AGENT')
    cfg.register_opts(sriov_nic_opts, 'SRIOV_NIC')
