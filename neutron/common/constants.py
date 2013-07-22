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

NET_STATUS_ACTIVE = 'ACTIVE'
NET_STATUS_BUILD = 'BUILD'
NET_STATUS_DOWN = 'DOWN'
NET_STATUS_ERROR = 'ERROR'

PORT_STATUS_ACTIVE = 'ACTIVE'
PORT_STATUS_BUILD = 'BUILD'
PORT_STATUS_DOWN = 'DOWN'
PORT_STATUS_ERROR = 'ERROR'

DEVICE_OWNER_ROUTER_INTF = "network:router_interface"
DEVICE_OWNER_ROUTER_GW = "network:router_gateway"
DEVICE_OWNER_FLOATINGIP = "network:floatingip"
DEVICE_OWNER_DHCP = "network:dhcp"

FLOATINGIP_KEY = '_floatingips'
INTERFACE_KEY = '_interfaces'

IPv4 = 'IPv4'
IPv6 = 'IPv6'

ICMP_PROTOCOL = 1
TCP_PROTOCOL = 6
UDP_PROTOCOL = 17

DHCP_RESPONSE_PORT = 68

MIN_VLAN_TAG = 1
MAX_VLAN_TAG = 4094

EXT_NS = '_extension_ns'
XML_NS_V20 = 'http://openstack.org/quantum/api/v2.0'
XSI_NAMESPACE = "http://www.w3.org/2001/XMLSchema-instance"
XSI_ATTR = "xsi:nil"
XSI_NIL_ATTR = "xmlns:xsi"
ATOM_NAMESPACE = "http://www.w3.org/2005/Atom"
ATOM_XMLNS = "xmlns:atom"
ATOM_LINK_NOTATION = "{%s}link" % ATOM_NAMESPACE
TYPE_XMLNS = "xmlns:quantum"
TYPE_ATTR = "quantum:type"
VIRTUAL_ROOT_KEY = "_v_root"

TYPE_BOOL = "bool"
TYPE_INT = "int"
TYPE_LONG = "long"
TYPE_FLOAT = "float"
TYPE_LIST = "list"
TYPE_DICT = "dict"

AGENT_TYPE_DHCP = 'DHCP agent'
AGENT_TYPE_OVS = 'Open vSwitch agent'
AGENT_TYPE_LINUXBRIDGE = 'Linux bridge agent'
AGENT_TYPE_NEC = 'NEC plugin agent'
AGENT_TYPE_L3 = 'L3 agent'
AGENT_TYPE_LOADBALANCER = 'Loadbalancer agent'
L2_AGENT_TOPIC = 'N/A'

PAGINATION_INFINITE = 'infinite'

SORT_DIRECTION_ASC = 'asc'
SORT_DIRECTION_DESC = 'desc'

L3_AGENT_SCHEDULER_EXT_ALIAS = 'l3_agent_scheduler'
DHCP_AGENT_SCHEDULER_EXT_ALIAS = 'dhcp_agent_scheduler'
LBAAS_AGENT_SCHEDULER_EXT_ALIAS = 'lbaas_agent_scheduler'
