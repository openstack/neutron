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

from neutron_lib import constants as p_const


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
TUNNEL_NETWORK_TYPES = [p_const.TYPE_GRE, p_const.TYPE_VXLAN,
                        p_const.TYPE_GENEVE]

# --- OpenFlow table IDs

# --- Integration bridge (int_br)

LOCAL_SWITCHING = 0

# Various tables for DVR use of integration bridge flows
DVR_TO_SRC_MAC = 1
DVR_TO_SRC_MAC_VLAN = 2

CANARY_TABLE = 23

# Table for ARP poison/spoofing prevention rules
ARP_SPOOF_TABLE = 24

# Table for MAC spoof filtering
MAC_SPOOF_TABLE = 25

# Table to decide whether further filtering is needed
TRANSIENT_TABLE = 60

# Tables used for ovs firewall
BASE_EGRESS_TABLE = 71
RULES_EGRESS_TABLE = 72
ACCEPT_OR_INGRESS_TABLE = 73
BASE_INGRESS_TABLE = 81
RULES_INGRESS_TABLE = 82

OVS_FIREWALL_TABLES = (
    BASE_EGRESS_TABLE,
    RULES_EGRESS_TABLE,
    ACCEPT_OR_INGRESS_TABLE,
    BASE_INGRESS_TABLE,
    RULES_INGRESS_TABLE,
)

# Tables for parties interacting with ovs firewall
ACCEPTED_EGRESS_TRAFFIC_TABLE = 91
ACCEPTED_INGRESS_TRAFFIC_TABLE = 92
DROPPED_TRAFFIC_TABLE = 93
ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE = 94

# --- Tunnel bridge (tun_br)

# Various tables for tunneling flows
DVR_PROCESS = 1
PATCH_LV_TO_TUN = 2
GRE_TUN_TO_LV = 3
VXLAN_TUN_TO_LV = 4
GENEVE_TUN_TO_LV = 6

DVR_NOT_LEARN = 9
LEARN_FROM_TUN = 10
UCAST_TO_TUN = 20
ARP_RESPONDER = 21
FLOOD_TO_TUN = 22

# --- Physical Bridges (phys_brs)

# Various tables for DVR use of physical bridge flows
DVR_PROCESS_VLAN = 1
LOCAL_VLAN_TRANSLATION = 2
DVR_NOT_LEARN_VLAN = 3

# --- end of OpenFlow table IDs

# type for ARP reply in ARP header
ARP_REPLY = '0x2'

# Map tunnel types to tables number
TUN_TABLE = {p_const.TYPE_GRE: GRE_TUN_TO_LV,
             p_const.TYPE_VXLAN: VXLAN_TUN_TO_LV,
             p_const.TYPE_GENEVE: GENEVE_TUN_TO_LV}


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

EXTENSION_DRIVER_TYPE = 'ovs'

# ovs datapath types
OVS_DATAPATH_SYSTEM = 'system'
OVS_DATAPATH_NETDEV = 'netdev'
OVS_DPDK_VHOST_USER = 'dpdkvhostuser'
OVS_DPDK_VHOST_USER_CLIENT = 'dpdkvhostuserclient'

OVS_DPDK_PORT_TYPES = [OVS_DPDK_VHOST_USER, OVS_DPDK_VHOST_USER_CLIENT]

# default ovs vhost-user socket location
VHOST_USER_SOCKET_DIR = '/var/run/openvswitch'

MAX_DEVICE_RETRIES = 5

# OpenFlow version constants
OPENFLOW10 = "OpenFlow10"
OPENFLOW11 = "OpenFlow11"
OPENFLOW12 = "OpenFlow12"
OPENFLOW13 = "OpenFlow13"
OPENFLOW14 = "OpenFlow14"
OPENFLOW15 = "OpenFlow15"

OPENFLOW_MAX_PRIORITY = 65535

# A placeholder for dead vlans.
DEAD_VLAN_TAG = p_const.MAX_VLAN_TAG + 1

# callback resource for setting 'bridge_name' in the 'binding:vif_details'
OVS_BRIDGE_NAME = 'ovs_bridge_name'

# callback resource for notifying to ovsdb handler
OVSDB_RESOURCE = 'ovsdb'

# Used in ovs port 'external_ids' in order mark it for no cleanup when
# ovs_cleanup script is used.
SKIP_CLEANUP = 'skip_cleanup'
