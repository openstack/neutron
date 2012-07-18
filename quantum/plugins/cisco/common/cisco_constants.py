# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2011 Cisco Systems, Inc.  All rights reserved.
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


PLUGINS = 'PLUGINS'
INVENTORY = 'INVENTORY'

PORT_STATE = 'port-state'
PORT_UP = "ACTIVE"
PORT_DOWN = "DOWN"

UUID = 'uuid'
TENANTID = 'tenant_id'
NETWORKID = 'network_id'
NETWORKNAME = 'name'
NETWORKPORTS = 'ports'
INTERFACEID = 'interface_id'
PORTSTATE = 'state'
PORTID = 'port_id'
PPNAME = 'name'
PPVLANID = 'vlan_id'
PPQOS = 'qos'
PPID = 'portprofile_id'
PPDEFAULT = 'default'
VLANID = 'vlan_id'
VLANNAME = 'vlan_name'
PORTPROFILENAME = 'portprofile_name'
QOS = 'qos'

ATTACHMENT = 'attachment'
PORT_ID = 'port-id'

NET_ID = 'net-id'
NET_NAME = 'net-name'
NET_PORTS = 'net-ports'
NET_VLAN_NAME = 'net-vlan-name'
NET_VLAN_ID = 'net-vlan-id'
NET_TENANTS = 'net-tenants'

TENANT_ID = 'tenant-id'
TENANT_NETWORKS = 'tenant-networks'
TENANT_NAME = 'tenant-name'
TENANT_PORTPROFILES = 'tenant-portprofiles'
TENANT_QOS_LEVELS = 'tenant-qos-levels'
TENANT_CREDENTIALS = 'tenant-credentials'

PORT_PROFILE = 'port-profile'
PROFILE_ID = 'profile_id'
PROFILE_NAME = 'profile_name'
PROFILE_VLAN_NAME = 'profile-vlan-name'
PROFILE_VLAN_ID = 'vlan-id'
PROFILE_QOS = 'qos_name'
PROFILE_ASSOCIATIONS = 'assignment'

QOS_LEVEL_ID = 'qos_id'
QOS_LEVEL_NAME = 'qos_name'
QOS_LEVEL_ASSOCIATIONS = 'qos-level-associations'
QOS_LEVEL_DESCRIPTION = 'qos_desc'

CREDENTIAL_ID = 'credential_id'
CREDENTIAL_NAME = 'credential_name'
CREDENTIAL_USERNAME = 'user_name'
CREDENTIAL_PASSWORD = 'password'
MASKED_PASSWORD = '********'

USERNAME = 'username'
PASSWORD = 'password'

LOGGER_COMPONENT_NAME = "cisco_plugin"

BLADE_INTF_DN = "blade_intf_distinguished_name"
BLADE_INTF_ORDER = "blade-intf-order"
BLADE_INTF_LINK_STATE = "blade-intf-link-state"
BLADE_INTF_OPER_STATE = "blade-intf-operational-state"
BLADE_INTF_INST_TYPE = "blade-intf-inst-type"
BLADE_INTF_RHEL_DEVICE_NAME = "blade-intf-rhel-device-name"
BLADE_INTF_DYNAMIC = "dynamic"
BLADE_INTF_STATE_UNKNOWN = "unknown"
BLADE_INTF_STATE_UNALLOCATED = "unallocated"
BLADE_INTF_RESERVED = "blade-intf-reserved"
BLADE_INTF_UNRESERVED = "blade-intf-unreserved"
BLADE_INTF_RESERVATION = "blade-intf-reservation-status"
BLADE_UNRESERVED_INTF_COUNT = "blade-unreserved-interfaces-count"
BLADE_INTF_DATA = "blade-intf-data"

LEAST_RSVD_BLADE_UCSM = "least-reserved-blade-ucsm"
LEAST_RSVD_BLADE_CHASSIS = "least-reserved-blade-chassis"
LEAST_RSVD_BLADE_ID = "least-reserved-blade-id"
LEAST_RSVD_BLADE_DATA = "least-reserved-blade-data"

RESERVED_NIC_HOSTNAME = "reserved-dynamic-nic-hostname"
RESERVED_NIC_NAME = "reserved-dynamic-nic-device-name"

RESERVED_INTERFACE_UCSM = "reserved-interface-ucsm-ip"
RESERVED_INTERFACE_CHASSIS = "reserved-interface-chassis"
RESERVED_INTERFACE_BLADE = "reserved-interface-blade"
RESERVED_INTERFACE_DN = "reserved-interface-dn"

RHEL_DEVICE_NAME_REPFIX = "eth"

UCS_PLUGIN = 'ucs_plugin'
NEXUS_PLUGIN = 'nexus_plugin'
UCS_INVENTORY = 'ucs_inventory'
NEXUS_INVENTORY = 'nexus_inventory'

PLUGIN_OBJ_REF = 'plugin-obj-ref'
PARAM_LIST = 'param-list'

DEVICE_IP = 'device_ip'

NO_VLAN_ID = 0

HOST_LIST = 'host_list'
HOST_1 = 'host_1'

VIF_DESC = 'vif_desc'
DEVICENAME = 'device'
UCSPROFILE = 'portprofile'

IP_ADDRESS = 'ip_address'
CHASSIS_ID = 'chassis_id'
BLADE_ID = 'blade_id'
HOST_NAME = 'host_name'

INSTANCE_ID = 'instance_id'
VIF_ID = 'vif_id'
PROJECT_ID = 'project_id'

UCS_INVENTORY = 'ucs_inventory'
LEAST_RSVD_BLADE_DICT = 'least_rsvd_blade_dict'

UCSM_IP = 'ucsm_ip_address'

NETWORK_ADMIN = 'network_admin'

NETID_LIST = 'net_id_list'

DELIMITERS = "[,;:\b\s]"

UUID_LENGTH = 36

UNPLUGGED = '(detached)'

ASSOCIATION_STATUS = 'association_status'

ATTACHED = 'attached'

DETACHED = 'detached'

NETWORK = 'network'
PORT = 'port'
BASE_PLUGIN_REF = 'base_plugin_ref'
CONTEXT = 'context'
SUBNET = 'subnet'
