# Copyright 2022 Red Hat, Inc.
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

import collections

from neutron.agent.linux import utils as linux_utils
from neutron.privileged.agent.linux import devlink as priv_devlink


PortIndex = collections.namedtuple(
    'PortIndex', ['name', 'pf_pci', 'pf_num', 'vf_num', 'is_parent'])


def get_port(port_name):
    """Retrieves the devlink port information, including the PF name."""
    ports = priv_devlink.get_port_list()
    # Build port index, with PF reference and VF index.
    port_indexes = []
    ret = None
    for port in ports:
        pf_pci = linux_utils.get_attr(port, 'DEVLINK_ATTR_DEV_NAME')
        name = linux_utils.get_attr(port, 'DEVLINK_ATTR_PORT_NETDEV_NAME')
        index = linux_utils.get_attr(port, 'DEVLINK_ATTR_PORT_INDEX')
        pf_num = index >> 16
        is_parent = index & 0xFFFF == 0xFFFF
        vf_num = linux_utils.get_attr(port, 'DEVLINK_ATTR_PORT_PCI_VF_NUMBER')
        port_indexes.append(PortIndex(name, pf_pci, pf_num, vf_num, is_parent))

        if name == port_name:
            ret = {'pf_pci': pf_pci,
                   'pf_num': pf_num,
                   'pf_name': None,
                   'vf_num': vf_num,
                   'vf_name': name,
                   }

    if ret:
        for port in port_indexes:
            if port.pf_num == ret['pf_num'] and port.is_parent:
                ret['pf_name'] = port.name

    return ret
