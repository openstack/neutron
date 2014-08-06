# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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
CSR (IOS-XE) XML-based configuration snippets
"""

# The standard Template used to interact with IOS-XE(CSR).
# This template is added by the netconf client
# EXEC_CONF_SNIPPET = """
#       <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
#         <configure>
#           <__XML__MODE__exec_configure>%s
#           </__XML__MODE__exec_configure>
#         </configure>
#       </config>
# """


#=================================================#
# Set ip address on an interface
# $(config)interface GigabitEthernet 1
# $(config)ip address 10.0.100.1 255.255.255.0
#=================================================#
SET_INTC = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>ip address %s %s</cmd>
        </cli-config-data>
</config>
"""

#=================================================#
# Enable an interface
# $(config)interface GigabitEthernet 1
# $(config)no shutdown
#=================================================#
ENABLE_INTF = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>no shutdown</cmd>
        </cli-config-data>
</config>
"""

#=================================================#
# Create VRF
# $(config)ip routing
# $(config)ip vrf nrouter-e7d4y5
#=================================================#
CREATE_VRF = """
<config>
        <cli-config-data>
            <cmd>ip routing</cmd>
            <cmd>ip vrf %s</cmd>
        </cli-config-data>
</config>
"""

#=================================================#
# Remove VRF
# $(config)ip routing
# $(config)no ip vrf nrouter-e7d4y5
#=================================================#
REMOVE_VRF = """
<config>
        <cli-config-data>
            <cmd>ip routing</cmd>
            <cmd>no ip vrf %s</cmd>
        </cli-config-data>
</config>
"""

#=================================================#
# Create Subinterface
# $(config)interface GigabitEthernet 2.500
# $(config)encapsulation dot1Q 500
# $(config)vrf forwarding nrouter-e7d4y5
# $(config)ip address 192.168.0.1 255.255.255.0
#=================================================#
CREATE_SUBINTERFACE = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>encapsulation dot1Q %s</cmd>
            <cmd>ip vrf forwarding %s</cmd>
            <cmd>ip address %s %s</cmd>
        </cli-config-data>
</config>

"""

#=================================================#
# Remove Subinterface
# $(config)no interface GigabitEthernet 2.500
#=================================================#
REMOVE_SUBINTERFACE = """
<config>
        <cli-config-data>
            <cmd>no interface %s</cmd>
        </cli-config-data>
</config>
"""

#=================================================#
# Enable HSRP on a Subinterface
# $(config)interface GigabitEthernet 2.500
# $(config)vrf forwarding nrouter-e7d4y5
# $(config)standby version 2
# $(config)standby <group> priority <priority>
# $(config)standby <group> ip <ip>
#=================================================#
SET_INTC_HSRP = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>ip vrf forwarding %s</cmd>
            <cmd>standby version 2</cmd>
            <cmd>standby %s priority %s</cmd>
            <cmd>standby %s ip %s</cmd>
        </cli-config-data>
</config>

"""

#=================================================#
# Remove HSRP on a Subinterface
# $(config)interface GigabitEthernet 2.500
# $(config)no standby version 2
# $(config)no standby <group>
#=================================================#
REMOVE_INTC_HSRP = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>no standby %s</cmd>
            <cmd>no standby version 2</cmd>
        </cli-config-data>
</config>

"""


#=================================================#
# Create Access Control List
# $(config)ip access-list standard acl_500
# $(config)permit 192.168.0.1 255.255.255.0
#=================================================#
CREATE_ACL = """
<config>
        <cli-config-data>
            <cmd>ip access-list standard %s</cmd>
            <cmd>permit %s %s</cmd>
        </cli-config-data>
</config>
"""

#=================================================#
# Remove Access Control List
# $(config)no ip access-list standard acl_500
#=================================================#
REMOVE_ACL = """
<config>
        <cli-config-data>
            <cmd>no ip access-list standard %s</cmd>
        </cli-config-data>
</config>
"""

#=========================================================================#
# Set Dynamic source translation on an interface
# Syntax: ip nat inside source list <acl_no> interface <interface>
# .......vrf <vrf_name> overload
# eg: $(config)ip nat inside source list acl_500
#    ..........interface GigabitEthernet3.100 vrf nrouter-e7d4y5 overload
#========================================================================#
SNAT_CFG = "ip nat inside source list %s interface %s vrf %s overload"

SET_DYN_SRC_TRL_INTFC = """
<config>
        <cli-config-data>
            <cmd>ip nat inside source list %s interface %s vrf %s
            overload</cmd>
        </cli-config-data>
</config>

"""

#=========================================================================#
# Remove Dynamic source translation on an interface
# Syntax: no ip nat inside source list <acl_no> interface <interface>
# .......vrf <vrf_name> overload
# eg: $(config)no ip nat inside source list acl_500
#    ..........interface GigabitEthernet3.100 vrf nrouter-e7d4y5 overload
#========================================================================#
REMOVE_DYN_SRC_TRL_INTFC = """
<config>
        <cli-config-data>
            <cmd>no ip nat inside source list %s interface %s vrf %s
            overload</cmd>
        </cli-config-data>
</config>

"""

#=================================================#
# Set NAT
# Syntax : interface <interface>
#          ip nat <inside|outside>
#=================================================#
SET_NAT = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>ip nat %s</cmd>
        </cli-config-data>
</config>
"""

#=================================================#
# Remove NAT
# Syntax : interface <interface>
#          no ip nat <inside|outside>
#=================================================#
REMOVE_NAT = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>no ip nat %s</cmd>
        </cli-config-data>
</config>
"""

#=========================================================================#
# Set Static source translation on an interface
# Syntax: ip nat inside source static <fixed_ip> <floating_ip>
# .......vrf <vrf_name> match-in-vrf
# eg: $(config)ip nat inside source static 192.168.0.1 121.158.0.5
#    ..........vrf nrouter-e7d4y5 match-in-vrf
#========================================================================#
SET_STATIC_SRC_TRL = """
<config>
        <cli-config-data>
            <cmd>ip nat inside source static %s %s vrf %s match-in-vrf</cmd>
        </cli-config-data>
</config>

"""

#=========================================================================#
# Remove Static source translation on an interface
# Syntax: no ip nat inside source static <fixed_ip> <floating_ip>
# .......vrf <vrf_name> match-in-vrf
# eg: $(config)no ip nat inside source static 192.168.0.1 121.158.0.5
#    ..........vrf nrouter-e7d4y5 match-in-vrf
#========================================================================#
REMOVE_STATIC_SRC_TRL = """
<config>
        <cli-config-data>
            <cmd>no ip nat inside source static %s %s vrf %s match-in-vrf</cmd>
        </cli-config-data>
</config>

"""

#=============================================================================#
# Set ip route
# Syntax: ip route vrf <vrf-name> <destination> <mask> [<interface>] <next hop>
# eg: $(config)ip route vrf nrouter-e7d4y5 8.8.0.0  255.255.0.0 10.0.100.255
#=============================================================================#
SET_IP_ROUTE = """
<config>
        <cli-config-data>
            <cmd>ip route vrf %s %s %s %s</cmd>
        </cli-config-data>
</config>
"""

#=============================================================================#
# Remove ip route
# Syntax: no ip route vrf <vrf-name> <destination> <mask>
#        [<interface>] <next hop>
# eg: $(config)no ip route vrf nrouter-e7d4y5 8.8.0.0  255.255.0.0 10.0.100.255
#=============================================================================#
REMOVE_IP_ROUTE = """
<config>
        <cli-config-data>
            <cmd>no ip route vrf %s %s %s %s</cmd>
        </cli-config-data>
</config>
"""
#=============================================================================#
# Set default ip route
# Syntax: ip route vrf <vrf-name> 0.0.0.0 0.0.0.0 [<interface>] <next hop>
# eg: $(config)ip route vrf nrouter-e7d4y5 0.0.0.0  0.0.0.0 10.0.100.255
#=============================================================================#
DEFAULT_ROUTE_CFG = 'ip route vrf %s 0.0.0.0 0.0.0.0 %s'

SET_DEFAULT_ROUTE = """
<config>
        <cli-config-data>
            <cmd>ip route vrf %s 0.0.0.0 0.0.0.0 %s</cmd>
        </cli-config-data>
</config>
"""

#=============================================================================#
# Remove default ip route
# Syntax: ip route vrf <vrf-name> 0.0.0.0 0.0.0.0 [<interface>] <next hop>
# eg: $(config)ip route vrf nrouter-e7d4y5 0.0.0.0  0.0.0.0 10.0.100.255
#=============================================================================#
REMOVE_DEFAULT_ROUTE = """
<config>
        <cli-config-data>
            <cmd>no ip route vrf %s 0.0.0.0 0.0.0.0 %s</cmd>
        </cli-config-data>
</config>
"""

#=============================================================================#
# Clear dynamic nat translations. This is used to clear any nat bindings before
# we can turn off NAT on an interface
# Syntax: clear ip nat translation [forced]
#=============================================================================#
# CLEAR_DYN_NAT_TRANS = """
# <oper-data-format-text-block>
#     <exec>clear ip nat translation forced</exec>
# </oper-data-format-text-block>
# """
CLEAR_DYN_NAT_TRANS = """
<config>
        <cli-config-data>
            <cmd>do clear ip nat translation forced</cmd>
        </cli-config-data>
</config>
"""
