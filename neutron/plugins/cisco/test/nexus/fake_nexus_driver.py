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


class CiscoNEXUSFakeDriver():
    """Nexus Driver Fake Class."""

    def __init__(self):
        pass

    def nxos_connect(self, nexus_host, nexus_ssh_port, nexus_user,
                     nexus_password):
        """Make the fake connection to the Nexus Switch."""
        pass

    def create_xml_snippet(self, cutomized_config):
        """Create XML snippet.

        Creates the Proper XML structure for the Nexus Switch
        Configuration.
        """
        pass

    def enable_vlan(self, mgr, vlanid, vlanname):
        """Create a VLAN on Nexus Switch given the VLAN ID and Name."""
        pass

    def disable_vlan(self, mgr, vlanid):
        """Delete a VLAN on Nexus Switch given the VLAN ID."""
        pass

    def disable_switch_port(self, mgr, interface):
        """Disable trunk mode an interface on Nexus Switch."""
        pass

    def enable_vlan_on_trunk_int(self, mgr, etype, interface, vlanid):
        """Enable vlan on trunk interface.

        Enable trunk mode vlan access an interface on Nexus Switch given
        VLANID.
        """
        pass

    def disable_vlan_on_trunk_int(self, mgr, interface, vlanid):
        """Disables vlan in trunk interface.

        Enables trunk mode vlan access an interface on Nexus Switch given
        VLANID.
        """
        pass

    def create_vlan(self, vlan_name, vlan_id, nexus_host, nexus_user,
                    nexus_password, nexus_ports, nexus_ssh_port, vlan_ids):
        """Create VLAN and enable it on interface.

        Creates a VLAN and Enable on trunk mode an interface on Nexus Switch
        given the VLAN ID and Name and Interface Number.
        """
        pass

    def delete_vlan(self, vlan_id, nexus_host, nexus_user, nexus_password,
                    nexus_ports, nexus_ssh_port):
        """Delete VLAN.

        Delete a VLAN and Disables trunk mode an interface on Nexus Switch
        given the VLAN ID and Interface Number.
        """
        pass

    def build_vlans_cmd(self):
        """Build a string with all the VLANs on the same Switch."""
        pass

    def add_vlan_int(self, vlan_id, nexus_host, nexus_user, nexus_password,
                     nexus_ports, nexus_ssh_port, vlan_ids=None):
        """Add a vlan from interfaces on the Nexus switch given the VLAN ID."""
        pass

    def remove_vlan_int(self, vlan_id, nexus_host, nexus_user, nexus_password,
                        nexus_ports, nexus_ssh_port):
        """Remove vlan from interfaces.

        Removes a vlan from interfaces on the Nexus switch given the VLAN ID.
        """
        pass
