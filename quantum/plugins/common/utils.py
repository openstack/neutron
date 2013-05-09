# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Cisco Systems, Inc.
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

"""
Common utilities and helper functions for Openstack Networking Plugins.
"""

from quantum.common import exceptions as q_exc


def parse_network_vlan_range(network_vlan_range):
    """Interpret a string as network[:vlan_begin:vlan_end]."""
    entry = network_vlan_range.strip()
    if ':' in entry:
        try:
            network, vlan_min, vlan_max = entry.split(':')
            vlan_min, vlan_max = int(vlan_min), int(vlan_max)
        except ValueError as ex:
            raise q_exc.NetworkVlanRangeError(range=entry, error=ex)
        return network, (vlan_min, vlan_max)
    else:
        return entry, None


def parse_network_vlan_ranges(network_vlan_ranges_cfg_entries):
    """Interpret a list of strings as network[:vlan_begin:vlan_end] entries."""
    networks = {}
    for entry in network_vlan_ranges_cfg_entries:
        network, vlan_range = parse_network_vlan_range(entry)
        if vlan_range:
            networks.setdefault(network, []).append(vlan_range)
        else:
            networks.setdefault(network, [])
    return networks
