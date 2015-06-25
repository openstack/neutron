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

from neutron.agent.common import config


def parse_exclude_devices(exclude_list):
    """Parse Exclude devices list

    parses excluded device list in the form:
    dev_name:pci_dev_1;pci_dev_2
    @param exclude list: list of string pairs in "key:value" format
                        the key part represents the network device name
                        the value part is a list of PCI slots separated by ";"
    """
    exclude_mapping = {}
    for dev_mapping in exclude_list:
        try:
            dev_name, exclude_devices = dev_mapping.split(":", 1)
        except ValueError:
            raise ValueError(_("Invalid mapping: '%s'") % dev_mapping)
        dev_name = dev_name.strip()
        if not dev_name:
            raise ValueError(_("Missing key in mapping: '%s'") % dev_mapping)
        if dev_name in exclude_mapping:
            raise ValueError(_("Device %(dev_name)s in mapping: %(mapping)s "
                               "not unique") % {'dev_name': dev_name,
                                                'mapping': dev_mapping})
        exclude_devices_list = exclude_devices.split(";")
        exclude_devices_set = set()
        for dev in exclude_devices_list:
            dev = dev.strip()
            if dev:
                exclude_devices_set.add(dev)
        exclude_mapping[dev_name] = exclude_devices_set
    return exclude_mapping

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
                help=_("List of <physical_network>:<network_device> mapping "
                       "physical network names to the agent's node-specific "
                       "physical network device of SR-IOV physical "
                       "function to be used for VLAN networks. "
                       "All physical networks listed in network_vlan_ranges "
                       "on the server should have mappings to appropriate "
                       "interfaces on each agent")),
    cfg.ListOpt('exclude_devices',
                default=DEFAULT_EXCLUDE_DEVICES,
                help=_("List of <network_device>:<excluded_devices> "
                       "mapping network_device to the agent's node-specific "
                       "list of virtual functions that should not be used "
                       "for virtual networking. excluded_devices is a "
                       "semicolon separated list of virtual functions "
                       "(BDF format).to exclude from network_device. "
                       "The network_device in the mapping should appear in "
                       "the physical_device_mappings list.")),
]


cfg.CONF.register_opts(agent_opts, 'AGENT')
cfg.CONF.register_opts(sriov_nic_opts, 'SRIOV_NIC')
config.register_agent_state_opts_helper(cfg.CONF)
