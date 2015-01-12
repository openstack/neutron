# Copyright 2013 Brocade Communications System, Inc.
# All rights reserved.
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


"""FAKE DRIVER, for unit tests purposes.

Brocade NOS Driver implements NETCONF over SSHv2 for
Neutron network life-cycle management.
"""


class NOSdriver(object):
    """NOS NETCONF interface driver for Neutron network.

    Fake: Handles life-cycle management of Neutron network,
    leverages AMPP on NOS
    (for use by unit tests, avoids touching any hardware)
    """

    def __init__(self):
        pass

    def connect(self, host, username, password):
        """Connect via SSH and initialize the NETCONF session."""
        pass

    def create_network(self, host, username, password, net_id):
        """Creates a new virtual network."""
        pass

    def delete_network(self, host, username, password, net_id):
        """Deletes a virtual network."""
        pass

    def associate_mac_to_network(self, host, username, password,
                                 net_id, mac):
        """Associates a MAC address to virtual network."""
        pass

    def dissociate_mac_from_network(self, host, username, password,
                                    net_id, mac):
        """Dissociates a MAC address from virtual network."""
        pass

    def create_vlan_interface(self, mgr, vlan_id):
        """Configures a VLAN interface."""
        pass

    def delete_vlan_interface(self, mgr, vlan_id):
        """Deletes a VLAN interface."""
        pass

    def get_port_profiles(self, mgr):
        """Retrieves all port profiles."""
        pass

    def get_port_profile(self, mgr, name):
        """Retrieves a port profile."""
        pass

    def create_port_profile(self, mgr, name):
        """Creates a port profile."""
        pass

    def delete_port_profile(self, mgr, name):
        """Deletes a port profile."""
        pass

    def activate_port_profile(self, mgr, name):
        """Activates a port profile."""
        pass

    def deactivate_port_profile(self, mgr, name):
        """Deactivates a port profile."""
        pass

    def associate_mac_to_port_profile(self, mgr, name, mac_address):
        """Associates a MAC address to a port profile."""
        pass

    def dissociate_mac_from_port_profile(self, mgr, name, mac_address):
        """Dissociates a MAC address from a port profile."""
        pass

    def create_vlan_profile_for_port_profile(self, mgr, name):
        """Creates VLAN sub-profile for port profile."""
        pass

    def configure_l2_mode_for_vlan_profile(self, mgr, name):
        """Configures L2 mode for VLAN sub-profile."""
        pass

    def configure_trunk_mode_for_vlan_profile(self, mgr, name):
        """Configures trunk mode for VLAN sub-profile."""
        pass

    def configure_allowed_vlans_for_vlan_profile(self, mgr, name, vlan_id):
        """Configures allowed VLANs for VLAN sub-profile."""
        pass
