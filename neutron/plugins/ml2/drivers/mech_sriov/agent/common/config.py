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


from neutron._i18n import _
from neutron.conf.plugins.ml2.drivers.mech_sriov import agent_common as \
     agent_common_config
from neutron.plugins.ml2.drivers.agent import config as cagt_config  # noqa


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


agent_common_config.register_agent_sriov_nic_opts()
