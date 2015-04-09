# Copyright (c) 2012 OpenStack Foundation.
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

from neutron.plugins.common import constants as p_const


# Special vlan_id value in ovs_vlan_allocations table indicating flat network
FLAT_VLAN_ID = -1

# Topic for tunnel notifications between the plugin and agent
TUNNEL = 'tunnel'

# Name prefixes for veth device or patch port pair linking the integration
# bridge with the physical bridge for a physical network
PEER_INTEGRATION_PREFIX = 'int-'
PEER_PHYSICAL_PREFIX = 'phy-'

# Nonexistent peer used to create patch ports without associating them, it
# allows to define flows before association
NONEXISTENT_PEER = 'nonexistent-peer'

# The different types of tunnels
TUNNEL_NETWORK_TYPES = [p_const.TYPE_GRE, p_const.TYPE_VXLAN]

# Various tables for DVR use of integration bridge flows
LOCAL_SWITCHING = 0
DVR_TO_SRC_MAC = 1
DVR_TO_SRC_MAC_VLAN = 2

# Various tables for tunneling flows
DVR_PROCESS = 1
PATCH_LV_TO_TUN = 2
GRE_TUN_TO_LV = 3
VXLAN_TUN_TO_LV = 4
DVR_NOT_LEARN = 9
LEARN_FROM_TUN = 10
UCAST_TO_TUN = 20
ARP_RESPONDER = 21
FLOOD_TO_TUN = 22

# Various tables for DVR use of physical bridge flows
DVR_PROCESS_VLAN = 1
LOCAL_VLAN_TRANSLATION = 2
DVR_NOT_LEARN_VLAN = 3

# Tables for integration bridge
# Table 0 is used for forwarding.
CANARY_TABLE = 23

# Table for ARP poison/spoofing prevention rules
ARP_SPOOF_TABLE = 24

# type for ARP reply in ARP header
ARP_REPLY = '0x2'

# Map tunnel types to tables number
TUN_TABLE = {p_const.TYPE_GRE: GRE_TUN_TO_LV,
             p_const.TYPE_VXLAN: VXLAN_TUN_TO_LV}

# The default respawn interval for the ovsdb monitor
DEFAULT_OVSDBMON_RESPAWN = 30

# Represent invalid OF Port
OFPORT_INVALID = -1

ARP_RESPONDER_ACTIONS = ('move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],'
                         'mod_dl_src:%(mac)s,'
                         'load:0x2->NXM_OF_ARP_OP[],'
                         'move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],'
                         'move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],'
                         'load:%(mac)#x->NXM_NX_ARP_SHA[],'
                         'load:%(ip)#x->NXM_OF_ARP_SPA[],'
                         'in_port')

# Represent ovs status
OVS_RESTARTED = 0
OVS_NORMAL = 1
OVS_DEAD = 2
