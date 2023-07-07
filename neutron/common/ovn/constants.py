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
import re
import uuid

from neutron_lib.api.definitions import portbindings
from neutron_lib import constants as const

OVN_SG_EXT_ID_KEY = 'neutron:security_group_id'
OVN_SG_RULE_EXT_ID_KEY = 'neutron:security_group_rule_id'
OVN_ML2_MECH_DRIVER_NAME = 'ovn'
OVN_NETWORK_NAME_EXT_ID_KEY = 'neutron:network_name'
OVN_NETWORK_MTU_EXT_ID_KEY = 'neutron:mtu'
OVN_PORT_NAME_EXT_ID_KEY = 'neutron:port_name'
OVN_PORT_EXT_ID_KEY = 'neutron:port_id'
OVN_PORT_FIP_EXT_ID_KEY = 'neutron:port_fip'
OVN_ROUTER_NAME_EXT_ID_KEY = 'neutron:router_name'
OVN_AZ_HINTS_EXT_ID_KEY = 'neutron:availability_zone_hints'
OVN_ROUTER_IS_EXT_GW = 'neutron:is_ext_gw'
OVN_GW_PORT_EXT_ID_KEY = 'neutron:gw_port_id'
OVN_SUBNET_EXT_ID_KEY = 'neutron:subnet_id'
OVN_SUBNET_EXT_IDS_KEY = 'neutron:subnet_ids'
OVN_SUBNET_POOL_EXT_ADDR_SCOPE4_KEY = 'neutron:subnet_pool_addr_scope4'
OVN_SUBNET_POOL_EXT_ADDR_SCOPE6_KEY = 'neutron:subnet_pool_addr_scope6'
OVN_PHYSNET_EXT_ID_KEY = 'neutron:provnet-physical-network'
OVN_NETTYPE_EXT_ID_KEY = 'neutron:provnet-network-type'
OVN_SEGID_EXT_ID_KEY = 'neutron:provnet-segmentation-id'
OVN_PROJID_EXT_ID_KEY = 'neutron:project_id'
OVN_DEVID_EXT_ID_KEY = 'neutron:device_id'
OVN_CIDRS_EXT_ID_KEY = 'neutron:cidrs'
OVN_FIP_EXT_ID_KEY = 'neutron:fip_id'
OVN_FIP_PORT_EXT_ID_KEY = 'neutron:fip_port_id'
OVN_FIP_EXT_MAC_KEY = 'neutron:fip_external_mac'
OVN_FIP_NET_ID = 'neutron:fip_network_id'
OVN_REV_NUM_EXT_ID_KEY = 'neutron:revision_number'
OVN_QOS_POLICY_EXT_ID_KEY = 'neutron:qos_policy_id'
OVN_SG_IDS_EXT_ID_KEY = 'neutron:security_group_ids'
OVN_DEVICE_OWNER_EXT_ID_KEY = 'neutron:device_owner'
OVN_LIVENESS_CHECK_EXT_ID_KEY = 'neutron:liveness_check_at'
METADATA_LIVENESS_CHECK_EXT_ID_KEY = 'neutron:metadata_liveness_check_at'
OVN_PORT_BINDING_PROFILE = portbindings.PROFILE
OVN_HOST_ID_EXT_ID_KEY = 'neutron:host_id'

MIGRATING_ATTR = 'migrating_to'
OVN_ROUTER_PORT_OPTION_KEYS = ['router-port', 'nat-addresses',
                               'exclude-lb-vips-from-garp']
OVN_GATEWAY_CHASSIS_KEY = 'redirect-chassis'
OVN_CHASSIS_REDIRECT = 'chassisredirect'
OVN_GATEWAY_NAT_ADDRESSES_KEY = 'nat-addresses'
OVN_ROUTER_PORT_EXCLUDE_LB_VIPS_GARP = 'exclude-lb-vips-from-garp'
OVN_DROP_PORT_GROUP_NAME = 'neutron_pg_drop'
OVN_ROUTER_PORT_GW_MTU_OPTION = 'gateway_mtu'

OVN_PROVNET_PORT_NAME_PREFIX = 'provnet-'
OVN_NAME_PREFIX = 'neutron-'

# Agent extension constants
OVN_AGENT_DESC_KEY = 'neutron:description'
OVN_AGENT_METADATA_SB_CFG_KEY = 'neutron:ovn-metadata-sb-cfg'
OVN_AGENT_METADATA_DESC_KEY = 'neutron:description-metadata'
OVN_AGENT_METADATA_ID_KEY = 'neutron:ovn-metadata-id'
OVN_CONTROLLER_AGENT = 'OVN Controller agent'
OVN_CONTROLLER_GW_AGENT = 'OVN Controller Gateway agent'
OVN_METADATA_AGENT = 'OVN Metadata agent'
OVN_CONTROLLER_TYPES = (OVN_CONTROLLER_AGENT,
                        OVN_CONTROLLER_GW_AGENT,
                        )

# OVN ACLs have priorities.  The highest priority ACL that matches is the one
# that takes effect.  Our choice of priority numbers is arbitrary, but it
# leaves room above and below the ACLs we create.  We only need two priorities.
# The first is for all the things we allow.  The second is for dropping traffic
# by default.
ACL_PRIORITY_ALLOW = 1002
ACL_PRIORITY_DROP = 1001

ACL_ACTION_DROP = 'drop'
ACL_ACTION_REJECT = 'reject'
ACL_ACTION_ALLOW_RELATED = 'allow-related'
ACL_ACTION_ALLOW_STATELESS = 'allow-stateless'
ACL_ACTION_ALLOW = 'allow'

# When a OVN L3 gateway is created, it needs to be bound to a chassis. In
# case a chassis is not found OVN_GATEWAY_INVALID_CHASSIS will be set in
# the options column of the Logical Router. This value is used to detect
# unhosted router gateways to schedule.
OVN_GATEWAY_INVALID_CHASSIS = 'neutron-ovn-invalid-chassis'

# NOTE(lucasagomes): These options were last synced from
# https://github.com/ovn-org/ovn/blob/feb5d6e81d5a0290aa3618a229c860d01200422e/lib/ovn-l7.h
#
# NOTE(lucasagomes): Whenever we update these lists please also update
# the related documentation at doc/source/ovn/dhcp_opts.rst
#
# Mappping between Neutron option names and OVN ones
SUPPORTED_DHCP_OPTS_MAPPING = {
    4: {'arp-timeout': 'arp_cache_timeout',
        'tcp-keepalive': 'tcp_keepalive_interval',
        'netmask': 'netmask',
        'router': 'router',
        'dns-server': 'dns_server',
        'log-server': 'log_server',
        'lpr-server': 'lpr_server',
        'domain-name': 'domain_name',
        'domain-search': 'domain_search_list',
        'swap-server': 'swap_server',
        'policy-filter': 'policy_filter',
        'router-solicitation': 'router_solicitation',
        'nis-server': 'nis_server',
        'ntp-server': 'ntp_server',
        'server-id': 'server_id',
        'tftp-server': 'tftp_server',
        'classless-static-route': 'classless_static_route',
        'ms-classless-static-route': 'ms_classless_static_route',
        'ip-forward-enable': 'ip_forward_enable',
        'router-discovery': 'router_discovery',
        'ethernet-encap': 'ethernet_encap',
        'default-ttl': 'default_ttl',
        'tcp-ttl': 'tcp_ttl',
        'mtu': 'mtu',
        'lease-time': 'lease_time',
        'T1': 'T1',
        'T2': 'T2',
        'bootfile-name': 'bootfile_name',
        'wpad': 'wpad',
        'path-prefix': 'path_prefix',
        'tftp-server-address': 'tftp_server_address',
        'server-ip-address': 'tftp_server_address',
        '1': 'netmask',
        '3': 'router',
        '6': 'dns_server',
        '7': 'log_server',
        '9': 'lpr_server',
        '15': 'domain_name',
        '16': 'swap_server',
        '21': 'policy_filter',
        '32': 'router_solicitation',
        '35': 'arp_cache_timeout',
        '38': 'tcp_keepalive_interval',
        '41': 'nis_server',
        '42': 'ntp_server',
        '54': 'server_id',
        '66': 'tftp_server',
        '121': 'classless_static_route',
        '249': 'ms_classless_static_route',
        '19': 'ip_forward_enable',
        '31': 'router_discovery',
        '36': 'ethernet_encap',
        '23': 'default_ttl',
        '37': 'tcp_ttl',
        '26': 'mtu',
        '51': 'lease_time',
        '58': 'T1',
        '59': 'T2',
        '67': 'bootfile_name',
        '119': 'domain_search_list',
        '252': 'wpad',
        '210': 'path_prefix',
        '150': 'tftp_server_address',
        '255': 'next_server'},
    6: {'server-id': 'server_id',
        'dns-server': 'dns_server',
        'domain-search': 'domain_search',
        'ia-addr': 'ia_addr',
        '2': 'server_id',
        '5': 'ia_addr',
        '24': 'domain_search',
        '23': 'dns_server'},
}

# OVN string type DHCP options
OVN_STR_TYPE_DHCP_OPTS = [
    'domain_name',
    'domain_search_list',
    'bootfile_name',
    'path_prefix',
    'wpad',
    'tftp_server']

# Special option for disabling DHCP via extra DHCP options
DHCP_DISABLED_OPT = 'dhcp_disabled'

DHCPV6_STATELESS_OPT = 'dhcpv6_stateless'

# When setting global DHCP options, these options will be ignored
# as they are required for basic network functions and will be
# set by Neutron.
GLOBAL_DHCP_OPTS_PROHIBIT_LIST = {
    4: ['server_id', 'lease_time', 'mtu', 'router', 'server_mac',
        'dns_server', 'classless_static_route'],
    6: ['dhcpv6_stateless', 'dns_server', 'server_id']}

CHASSIS_DATAPATH_NETDEV = 'netdev'
CHASSIS_IFACE_DPDKVHOSTUSER = 'dpdkvhostuser'

OVN_IPV6_ADDRESS_MODES = {
    const.IPV6_SLAAC: const.IPV6_SLAAC,
    const.DHCPV6_STATEFUL: const.DHCPV6_STATEFUL.replace('-', '_'),
    const.DHCPV6_STATELESS: const.DHCPV6_STATELESS.replace('-', '_')
}

DB_MAX_RETRIES = 60
DB_INITIAL_RETRY_INTERVAL = 0.5
DB_MAX_RETRY_INTERVAL = 1

TXN_COMMITTED = 'committed'
INITIAL_REV_NUM = -1

ACL_EXPECTED_COLUMNS_NBDB = (
    'external_ids', 'direction', 'log', 'priority',
    'name', 'action', 'severity', 'match')

# Resource types
TYPE_NETWORKS = 'networks'
TYPE_PORTS = 'ports'
TYPE_SECURITY_GROUP_RULES = 'security_group_rules'
TYPE_ROUTERS = 'routers'
TYPE_ROUTER_PORTS = 'router_ports'
TYPE_SECURITY_GROUPS = 'security_groups'
TYPE_FLOATINGIPS = 'floatingips'
TYPE_SUBNETS = 'subnets'

_TYPES_PRIORITY_ORDER = (
    TYPE_NETWORKS,
    TYPE_SECURITY_GROUPS,
    TYPE_SUBNETS,
    TYPE_ROUTERS,
    TYPE_PORTS,
    TYPE_ROUTER_PORTS,
    TYPE_FLOATINGIPS,
    TYPE_SECURITY_GROUP_RULES)

DB_CONSISTENCY_CHECK_INTERVAL = 300  # 5 minutes

# The order in which the resources should be created or updated by the
# maintenance task: Root ones first and leafs at the end.
MAINTENANCE_CREATE_UPDATE_TYPE_ORDER = {
    t: n for n, t in enumerate(_TYPES_PRIORITY_ORDER, 1)}

# The order in which the resources should be deleted by the maintenance
# task: Leaf ones first and roots at the end.
MAINTENANCE_DELETE_TYPE_ORDER = {
    t: n for n, t in enumerate(reversed(_TYPES_PRIORITY_ORDER), 1)}

# The addresses field to set in the logical switch port which has a
# peer router port (connecting to the logical router).
DEFAULT_ADDR_FOR_LSP_WITH_PEER = 'router'

# FIP ACTIONS
FIP_ACTION_ASSOCIATE = 'fip_associate'
FIP_ACTION_DISASSOCIATE = 'fip_disassociate'

# Loadbalancer constants
LRP_PREFIX = "lrp-"
RE_PORT_FROM_GWC = re.compile(r'(%s)([\w-]+)_([\w-]+)' % LRP_PREFIX)
LB_VIP_PORT_PREFIX = "ovn-lb-vip-"
LB_EXT_IDS_LS_REFS_KEY = 'ls_refs'
LB_EXT_IDS_LR_REF_KEY = 'lr_ref'
LB_EXT_IDS_POOL_PREFIX = 'pool_'
LB_EXT_IDS_LISTENER_PREFIX = 'listener_'
LB_EXT_IDS_MEMBER_PREFIX = 'member_'
LB_EXT_IDS_VIP_KEY = 'neutron:vip'
LB_EXT_IDS_VIP_FIP_KEY = 'neutron:vip_fip'
LB_EXT_IDS_VIP_PORT_ID_KEY = 'neutron:vip_port_id'

# Hash Ring constants
HASH_RING_NODES_TIMEOUT = 60
HASH_RING_TOUCH_INTERVAL = 30
HASH_RING_CACHE_TIMEOUT = 30
HASH_RING_ML2_GROUP = 'mechanism_driver'

# Maximum chassis count where a gateway port can be hosted
MAX_GW_CHASSIS = 5

UNKNOWN_ADDR = 'unknown'

PORT_CAP_SWITCHDEV = 'switchdev'
PORT_CAP_PARAM = 'capabilities'
VIF_DETAILS_PCI_VENDOR_INFO = 'pci_vendor_info'
VIF_DETAILS_PCI_SLOT = 'pci_slot'
VIF_DETAILS_PHYSICAL_NETWORK = 'physical_network'
VIF_DETAILS_CARD_SERIAL_NUMBER = 'card_serial_number'
VIF_DETAILS_PF_MAC_ADDRESS = 'pf_mac_address'
VIF_DETAILS_VF_NUM = 'vf_num'

# Port Binding Profile data validation
#
# To allow for validating multiple parameter sets that may contain some of the
# same keys, you can specify for which vnic_type and capability the parameter
# set is valid for.
#
# By leaving vnic_type and capability to the default of 'None' any parameter
# set that has a key which is present in the port binding data will be used for
# validation.
#
# The param_set type is Dict[str,Optional[List[any]]] where the key is used to
# match keys in the port binding data.  A value of 'None' means not to check
# type for this key, when a list of type classes is provided the data will be
# validated to be of one of the listed types.
OVNPortBindingProfileParamSet = collections.namedtuple(
    'OVNPortBindingProfileParamSet', ['param_set', 'vnic_type', 'capability'])
OVN_PORT_BINDING_PROFILE_PARAMS = [
    OVNPortBindingProfileParamSet({'parent_name': [str],
                                   'tag': [int]},
                                  None, None),
    OVNPortBindingProfileParamSet({'vtep-physical-switch': [str],
                                   'vtep-logical-switch': [str]},
                                  None, None),
    # For the two supported switchdev modes the data provided in the binding
    # profile is similar to what is used for Legacy SR-IOV.  However, the
    # `physical_network` value type is Union[str,None].  When a port is
    # attached to a project network backed by an overlay (tunneled) network the
    # value will be 'None'.  For the case of ports attached to a project
    # network backed by VLAN the value will be of type `str` and set to the
    # value provided in the `physical_network` tag in the Nova PCI Passthrough
    # configuration.
    #
    # Note that while the OVN driver provides services to Legacy SR-IOV
    # instances through the creation of external ports for DHCP and Metadata,
    # it does not bind the instance ports themselves.  Thus there is no
    # parameter set for them here.
    #
    # Switchdev capable device exposed on the hypervisor host.
    OVNPortBindingProfileParamSet({VIF_DETAILS_PCI_VENDOR_INFO: [str],
                                   VIF_DETAILS_PCI_SLOT: [str],
                                   VIF_DETAILS_PHYSICAL_NETWORK: [str,
                                                                  type(None)]},
                                  portbindings.VNIC_DIRECT,
                                  PORT_CAP_SWITCHDEV),
    # SmartNIC DPU. Switchdev capable device exposed on the SmartNIC DPU
    # control plane CPUs.
    OVNPortBindingProfileParamSet({VIF_DETAILS_PCI_VENDOR_INFO: [str],
                                   VIF_DETAILS_PCI_SLOT: [str],
                                   VIF_DETAILS_PHYSICAL_NETWORK: [str,
                                                                  type(None)],
                                   VIF_DETAILS_CARD_SERIAL_NUMBER: [str],
                                   VIF_DETAILS_PF_MAC_ADDRESS: [str],
                                   VIF_DETAILS_VF_NUM: [int]},
                                  portbindings.VNIC_REMOTE_MANAGED,
                                  None),
]

# The name of the port security group attribute is currently not in neutron nor
# neutron-lib api definitions or constants. To avoid importing the extension
# code directly we keep a copy here.
PORT_SECURITYGROUPS = 'security_groups'

# TODO(lucasagomes): Create constants for other LSP types
LSP_TYPE_LOCALNET = 'localnet'
LSP_TYPE_VIRTUAL = 'virtual'
LSP_TYPE_EXTERNAL = 'external'
LSP_TYPE_LOCALPORT = 'localport'
LSP_TYPE_ROUTER = 'router'
LSP_OPTIONS_VIRTUAL_PARENTS_KEY = 'virtual-parents'
LSP_OPTIONS_VIRTUAL_IP_KEY = 'virtual-ip'
LSP_OPTIONS_VIF_PLUG_TYPE_KEY = 'vif-plug-type'
LSP_OPTIONS_VIF_PLUG_MTU_REQUEST_KEY = 'vif-plug-mtu-request'
LSP_OPTIONS_VIF_PLUG_REPRESENTOR_PF_MAC_KEY = 'vif-plug:representor:pf-mac'
LSP_OPTIONS_VIF_PLUG_REPRESENTOR_VF_NUM_KEY = 'vif-plug:representor:vf-num'
LSP_OPTIONS_REQUESTED_CHASSIS_KEY = 'requested-chassis'
LSP_OPTIONS_MCAST_FLOOD_REPORTS = 'mcast_flood_reports'
LSP_OPTIONS_MCAST_FLOOD = 'mcast_flood'

LRP_OPTIONS_RESIDE_REDIR_CH = 'reside-on-redirect-chassis'
LRP_OPTIONS_REDIRECT_TYPE = 'redirect-type'
BRIDGE_REDIRECT_TYPE = "bridged"

# Port Binding types
PB_TYPE_VIRTUAL = 'virtual'

HA_CHASSIS_GROUP_DEFAULT_NAME = 'default_ha_chassis_group'
HA_CHASSIS_GROUP_HIGHEST_PRIORITY = 32767

# OVN igmp options
MCAST_SNOOP = 'mcast_snoop'
MCAST_FLOOD_UNREGISTERED = 'mcast_flood_unregistered'

EXTERNAL_PORT_TYPES = (portbindings.VNIC_DIRECT,
                       portbindings.VNIC_DIRECT_PHYSICAL,
                       portbindings.VNIC_MACVTAP,
                       portbindings.VNIC_BAREMETAL,
                       )

NEUTRON_AVAILABILITY_ZONES = 'neutron-availability-zones'
OVN_CMS_OPTIONS = 'ovn-cms-options'
CMS_OPT_CHASSIS_AS_GW = 'enable-chassis-as-gw'
CMS_OPT_AVAILABILITY_ZONES = 'availability-zones'
CMS_OPT_CARD_SERIAL_NUMBER = 'card-serial-number'

# OVN vlan transparency option
VLAN_PASSTHRU = 'vlan-passthru'

# OVN Placement API; used for minimum bandwidth scheduling allocation.
# NOTE(ralonsoh): rehome to neutron-lib
RP_HYPERVISORS = 'resource_provider_hypervisors'

# OVN mechanism driver constants.
OVN_RP_UUID = uuid.UUID('5533233b-800c-11eb-b1f4-000056b2f5b8')
OVN_SUPPORTED_VNIC_TYPES = [portbindings.VNIC_NORMAL,
                            portbindings.VNIC_DIRECT,
                            portbindings.VNIC_DIRECT_PHYSICAL,
                            portbindings.VNIC_MACVTAP,
                            portbindings.VNIC_VHOST_VDPA,
                            portbindings.VNIC_REMOTE_MANAGED,
                            portbindings.VNIC_BAREMETAL,
                            ]
