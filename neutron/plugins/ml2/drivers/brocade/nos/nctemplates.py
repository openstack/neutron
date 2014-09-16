# Copyright (c) 2014 Brocade Communications Systems, Inc.
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


"""NOS NETCONF XML Configuration Command Templates.

Interface Configuration Commands
"""

# Get NOS Version
SHOW_FIRMWARE_VERSION = (
    "show-firmware-version xmlns:nc="
    "'urn:brocade.com:mgmt:brocade-firmware-ext'"
)
GET_VCS_DETAILS = (
    'get-vcs-details xmlns:nc="urn:brocade.com:mgmt:brocade-vcs"'
)
SHOW_VIRTUAL_FABRIC = (
    'show-virtual-fabric xmlns:nc="urn:brocade.com:mgmt:brocade-vcs"'
)
GET_VIRTUAL_FABRIC_INFO = (
    'interface xmlns:nc="urn:brocade.com:mgmt:brocade-firmware-ext"'
)

NOS_VERSION = "./*/{urn:brocade.com:mgmt:brocade-firmware-ext}os-version"
VFAB_ENABLE = "./*/*/*/{urn:brocade.com:mgmt:brocade-vcs}vfab-enable"

# Create VLAN (vlan_id)
CREATE_VLAN_INTERFACE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <interface-vlan xmlns="urn:brocade.com:mgmt:brocade-interface">
            <interface>
                <vlan>
                    <name>{vlan_id}</name>
                </vlan>
            </interface>
        </interface-vlan>
    </config>
"""

# Delete VLAN (vlan_id)
DELETE_VLAN_INTERFACE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <interface-vlan xmlns="urn:brocade.com:mgmt:brocade-interface">
            <interface>
                <vlan operation="delete">
                    <name>{vlan_id}</name>
                </vlan>
            </interface>
        </interface-vlan>
    </config>
"""

#
# AMPP Life-cycle Management Configuration Commands
#

# Create AMPP port-profile (port_profile_name)
CREATE_PORT_PROFILE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <port-profile xmlns="urn:brocade.com:mgmt:brocade-port-profile">
            <name>{name}</name>
        </port-profile>
    </config>
"""

# Create VLAN sub-profile for port-profile (port_profile_name)
CREATE_VLAN_PROFILE_FOR_PORT_PROFILE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <port-profile xmlns="urn:brocade.com:mgmt:brocade-port-profile">
            <name>{name}</name>
            <vlan-profile/>
        </port-profile>
    </config>
"""

# Configure L2 mode for VLAN sub-profile (port_profile_name)
CONFIGURE_L2_MODE_FOR_VLAN_PROFILE_IN_DOMAIN = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <port-profile xmlns="urn:brocade.com:mgmt:brocade-port-profile">
            <name>{name}</name>
            <vlan-profile>
                <switchport-basic>
                   <basic/>
                </switchport-basic>
            </vlan-profile>
        </port-profile>
    </config>
"""

# Configure L2 mode for VLAN sub-profile (port_profile_name)
CONFIGURE_L2_MODE_FOR_VLAN_PROFILE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <port-profile xmlns="urn:brocade.com:mgmt:brocade-port-profile">
            <name>{name}</name>
            <vlan-profile>
                <switchport/>
            </vlan-profile>
        </port-profile>
    </config>
"""

# Configure trunk mode for VLAN sub-profile (port_profile_name)
CONFIGURE_TRUNK_MODE_FOR_VLAN_PROFILE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <port-profile xmlns="urn:brocade.com:mgmt:brocade-port-profile">
            <name>{name}</name>
            <vlan-profile>
                <switchport>
                    <mode>
                        <vlan-mode>trunk</vlan-mode>
                    </mode>
                </switchport>
            </vlan-profile>
        </port-profile>
    </config>
"""

# Configure allowed VLANs for VLAN sub-profile
# (port_profile_name, allowed_vlan, native_vlan)
CONFIGURE_ALLOWED_VLANS_FOR_VLAN_PROFILE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <port-profile xmlns="urn:brocade.com:mgmt:brocade-port-profile">
            <name>{name}</name>
            <vlan-profile>
                <switchport>
                    <trunk>
                        <allowed>
                            <vlan>
                                <add>{vlan_id}</add>
                            </vlan>
                        </allowed>
                    </trunk>
                </switchport>
            </vlan-profile>
        </port-profile>
    </config>
"""

# Delete port-profile (port_profile_name)
DELETE_PORT_PROFILE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <port-profile
xmlns="urn:brocade.com:mgmt:brocade-port-profile" operation="delete">
            <name>{name}</name>
        </port-profile>
    </config>
"""

# Activate port-profile (port_profile_name)
ACTIVATE_PORT_PROFILE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <port-profile-global xmlns="urn:brocade.com:mgmt:brocade-port-profile">
            <port-profile>
                <name>{name}</name>
                <activate/>
            </port-profile>
        </port-profile-global>
    </config>
"""

# Deactivate port-profile (port_profile_name)
DEACTIVATE_PORT_PROFILE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <port-profile-global xmlns="urn:brocade.com:mgmt:brocade-port-profile">
            <port-profile>
                <name>{name}</name>
                <activate
xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="delete" />
            </port-profile>
        </port-profile-global>
    </config>
"""

# Associate MAC address to port-profile (port_profile_name, mac_address)
ASSOCIATE_MAC_TO_PORT_PROFILE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <port-profile-global xmlns="urn:brocade.com:mgmt:brocade-port-profile">
            <port-profile>
                <name>{name}</name>
                <static>
                    <mac-address>{mac_address}</mac-address>
                </static>
            </port-profile>
        </port-profile-global>
    </config>
"""

# Dissociate MAC address from port-profile (port_profile_name, mac_address)
DISSOCIATE_MAC_FROM_PORT_PROFILE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <port-profile-global xmlns="urn:brocade.com:mgmt:brocade-port-profile">
            <port-profile>
                <name>{name}</name>
                <static
xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="delete">
                    <mac-address>{mac_address}</mac-address>
                </static>
            </port-profile>
        </port-profile-global>
    </config>
"""

# port-profile domain management commands
REMOVE_PORTPROFILE_FROM_DOMAIN = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <port-profile-domain xmlns="urn:brocade.com:mgmt:brocade-port-profile">
            <port-profile-domain-name>{domain_name}</port-profile-domain-name>
                <profile  operation="delete">
                    <profile-name>{name}</profile-name>
                </profile>
            </port-profile-domain>
    </config>
"""
# put port profile in default domain
CONFIGURE_PORTPROFILE_IN_DOMAIN = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <port-profile-domain xmlns="urn:brocade.com:mgmt:brocade-port-profile">
            <port-profile-domain-name>{domain_name}</port-profile-domain-name>
                <profile>
                    <profile-name>{name}</profile-name>
                </profile>
            </port-profile-domain>
    </config>
"""

#
# L3 Life-cycle Management Configuration Commands
#

# Create SVI and assign ippaddres (rbridge_id,vlan_id,ip_address)
CONFIGURE_SVI_WITH_IP_ADDRESS = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
         <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
            <rbridge-id>{rbridge_id}</rbridge-id>
            <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
                <ve>
                    <name>{vlan_id}</name>
                    <ip xmlns="urn:brocade.com:mgmt:brocade-ip-config">
                        <ip-config>
                          <address>
                             <address>{ip_address}</address>
                          </address>
                        </ip-config>
                    </ip>
                </ve>
            </interface>
         </rbridge-id>
    </config>
"""

# delete SVI (rbridge_id,vlan_id)
DELETE_SVI = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
         <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
            <rbridge-id>{rbridge_id}</rbridge-id>
            <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
                <ve operation="delete">
                    <name>{vlan_id}</name>
                </ve>
            </interface>
         </rbridge-id>
    </config>
"""

# Activate SVI (rbridge_id,vlan_id)
ACTIVATE_SVI = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
         <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
            <rbridge-id>{rbridge_id}</rbridge-id>
            <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
                <ve>
                    <name>{vlan_id}</name>
                    <shutdown xmlns="urn:brocade.com:mgmt:brocade-ip-config"
                    xc:operation="delete"></shutdown>
                </ve>
            </interface>
         </rbridge-id>
    </config>
"""

# Remove ipaddress from SVI (rbridge_id,vlan_id)
DECONFIGURE_IP_FROM_SVI = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
         <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
            <rbridge-id>{rbridge_id}</rbridge-id>
            <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
                <ve>
                    <name>{vlan_id}</name>
                    <ip xmlns="urn:brocade.com:mgmt:brocade-ip-config">
                        <ip-config>
                            <address xc:operation="delete">
                                <address>{gw_ip}</address>
                            </address>
                        </ip-config>
                    </ip>
                </ve>
            </interface>
         </rbridge-id>
    </config>
"""

# create vrf (rbridge_id,vrf_name)
CREATE_VRF = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
         <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
            <rbridge-id>{rbridge_id}</rbridge-id>
                <vrf xmlns="urn:brocade.com:mgmt:brocade-vrf">
                    <vrf-name>{vrf_name}</vrf-name>
                </vrf>
         </rbridge-id>
    </config>
"""


# delete vrf (rbridge_id,vrf_name)
DELETE_VRF = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
            <rbridge-id>{rbridge_id}</rbridge-id>
                <vrf xmlns="urn:brocade.com:mgmt:brocade-vrf"
                       xc:operation="delete">
                    <vrf-name>{vrf_name}</vrf-name>
                </vrf>
         </rbridge-id>
    </config>
"""

# configure route distinguisher for vrf (rbridge_id,vrf_name, rd)
CONFIGURE_RD_FOR_VRF = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
         <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
            <rbridge-id>{rbridge_id}</rbridge-id>
            <vrf xmlns="urn:brocade.com:mgmt:brocade-vrf">
                <vrf-name>{vrf_name}</vrf-name>
                <route-distiniguisher>{rd}</route-distiniguisher>
            </vrf>
         </rbridge-id>
    </config>
"""

# configure address-family for vrf (rbridge_id,vrf_name)
ADD_ADDRESS_FAMILY_FOR_VRF_V1 = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
         <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
            <rbridge-id>{rbridge_id}</rbridge-id>
            <vrf xmlns="urn:brocade.com:mgmt:brocade-vrf">
                <vrf-name>{vrf_name}</vrf-name>
                <address-family xmlns="urn:brocade.com:mgmt:brocade-vrf">
                    <ipv4>
                        <max-route>1200</max-route>
                    </ipv4>
                </address-family>
            </vrf>
         </rbridge-id>
    </config>
"""

# configure address-family for vrf (rbridge_id,vrf_name)
ADD_ADDRESS_FAMILY_FOR_VRF = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
         <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
            <rbridge-id>{rbridge_id}</rbridge-id>
            <vrf xmlns="urn:brocade.com:mgmt:brocade-vrf">
                <vrf-name>{vrf_name}</vrf-name>
                <address-family xmlns="urn:brocade.com:mgmt:brocade-vrf">
                    <ip>
                        <unicast/>
                    </ip>
                </address-family>
            </vrf>
         </rbridge-id>
    </config>
"""

# Bind vrf to SVI (rbridge_id,vlan_idi, vrf)
ADD_VRF_TO_SVI = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
         <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
            <rbridge-id>{rbridge_id}</rbridge-id>
            <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
                <ve>
                    <name>{vlan_id}</name>
                    <vrf xmlns="urn:brocade.com:mgmt:brocade-ip-config">
                        <forwarding>{vrf_name}</forwarding>
                    </vrf>
                </ve>
            </interface>
         </rbridge-id>
    </config>
"""

# unbind  vrf from SVI (rbridge_id,vlan_idi, vrf)
DELETE_VRF_FROM_SVI = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
         <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
            <rbridge-id>{rbridge_id}</rbridge-id>
            <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
                <ve>
                    <name>{vlan_id}</name>
                    <vrf xmlns="urn:brocade.com:mgmt:brocade-ip-config"
                            operation="delete">
                        <forwarding>{vrf_name}</forwarding>
                    </vrf>
                </ve>
            </interface>
         </rbridge-id>
    </config>
"""

#
# Constants
#

# Port profile naming convention for Neutron networks
OS_PORT_PROFILE_NAME = "openstack-profile-{id}"
OS_VRF_NAME = "osv-{id}"

# Port profile filter expressions
PORT_PROFILE_XPATH_FILTER = "/port-profile"
PORT_PROFILE_NAME_XPATH_FILTER = "/port-profile[name='{name}']"
