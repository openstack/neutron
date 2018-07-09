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
    cfg.ListOpt('resource_provider_bandwidths',
                default=[],
                help=_("Comma-separated list of "
                       "<network_device>:<egress_bw>:<ingress_bw> tuples, "
                       "showing the available bandwidth for the given device "
                       "in the given direction. The direction is meant from "
                       "VM perspective. Bandwidth is measured in kilobits per "
                       "second (kbps). The device must appear in "
                       "physical_device_mappings as the value. But not all "
                       "devices in physical_device_mappings must be listed "
                       "here. For a device not listed here we neither create "
                       "a resource provider in placement nor report "
                       "inventories against. An omitted direction means we do "
                       "not report an inventory for the corresponding "
                       "class.")),
    cfg.DictOpt('resource_provider_inventory_defaults',
                default={'allocation_ratio': 1.0,
                         'min_unit': 1,
                         'step_size': 1,
                         'reserved': 0},
                help=_("Key:value pairs to specify defaults used "
                       "while reporting resource provider inventories. "
                       "Possible keys with their types: "
                       "allocation_ratio:float, "
                       "max_unit:int, min_unit:int, "
                       "reserved:int, step_size:int, "
                       "See also: "
                       "https://developer.openstack.org/api-ref/placement/"
                       "#update-resource-provider-inventories")),
]


def register_agent_sriov_nic_opts(cfg=cfg.CONF):
    cfg.register_opts(sriov_nic_opts, 'SRIOV_NIC')
