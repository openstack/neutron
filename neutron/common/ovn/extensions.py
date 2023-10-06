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

from neutron_lib.api.definitions import address_group
from neutron_lib.api.definitions import address_scope
from neutron_lib.api.definitions import agent as agent_def
from neutron_lib.api.definitions import allowedaddresspairs
from neutron_lib.api.definitions import auto_allocated_topology
from neutron_lib.api.definitions import availability_zone as az_def
from neutron_lib.api.definitions import bgp
from neutron_lib.api.definitions import bgp_4byte_asn
from neutron_lib.api.definitions import bgp_dragentscheduler
from neutron_lib.api.definitions import default_subnetpools
from neutron_lib.api.definitions import dhcpagentscheduler
from neutron_lib.api.definitions import dns
from neutron_lib.api.definitions import dns_domain_keywords
from neutron_lib.api.definitions import dns_domain_ports
from neutron_lib.api.definitions import expose_port_forwarding_in_fip
from neutron_lib.api.definitions import external_net
from neutron_lib.api.definitions import extra_dhcp_opt
from neutron_lib.api.definitions import extraroute
from neutron_lib.api.definitions import filter_validation
from neutron_lib.api.definitions import fip_pf_description
from neutron_lib.api.definitions import fip_pf_detail
from neutron_lib.api.definitions import fip_pf_port_range
from neutron_lib.api.definitions import fip_port_details
from neutron_lib.api.definitions import floating_ip_port_forwarding
from neutron_lib.api.definitions import floatingip_pools
from neutron_lib.api.definitions import l3
from neutron_lib.api.definitions import l3_ext_gw_mode
from neutron_lib.api.definitions import logging
from neutron_lib.api.definitions import multiprovidernet
from neutron_lib.api.definitions import network_availability_zone
from neutron_lib.api.definitions import network_ip_availability
from neutron_lib.api.definitions import network_mtu
from neutron_lib.api.definitions import network_mtu_writable
from neutron_lib.api.definitions import pagination
from neutron_lib.api.definitions import port_device_profile
from neutron_lib.api.definitions import port_mac_address_regenerate
from neutron_lib.api.definitions import port_numa_affinity_policy
from neutron_lib.api.definitions import port_resource_request
from neutron_lib.api.definitions import port_security
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import portbindings_extended as pbe_ext
from neutron_lib.api.definitions import project_id
from neutron_lib.api.definitions import provider_net
from neutron_lib.api.definitions import qos
from neutron_lib.api.definitions import qos_bw_limit_direction
from neutron_lib.api.definitions import qos_default
from neutron_lib.api.definitions import qos_gateway_ip
from neutron_lib.api.definitions import qos_rule_type_details
from neutron_lib.api.definitions import qos_rule_type_filter
from neutron_lib.api.definitions import qos_rules_alias
from neutron_lib.api.definitions import quota_check_limit
from neutron_lib.api.definitions import rbac_address_scope
from neutron_lib.api.definitions import rbac_security_groups
from neutron_lib.api.definitions import router_availability_zone as raz_def
from neutron_lib.api.definitions import security_groups_normalized_cidr
from neutron_lib.api.definitions import security_groups_remote_address_group
from neutron_lib.api.definitions import security_groups_shared_filtering
from neutron_lib.api.definitions import segment as seg_def
from neutron_lib.api.definitions import sorting
from neutron_lib.api.definitions import stateful_security_group
from neutron_lib.api.definitions import subnet_dns_publish_fixed_ip
from neutron_lib.api.definitions import subnet_service_types
from neutron_lib.api.definitions import trunk
from neutron_lib.api.definitions import uplink_status_propagation
from neutron_lib.api.definitions import vlantransparent
from neutron_lib.api.definitions import vpn
from neutron_lib.api.definitions import vpn_endpoint_groups
from neutron_lib import constants

from neutron.extensions import quotasv2_detail

# NOTE(russellb) This remains in its own file (vs constants.py) because we want
# to be able to easily import it and export the info without any dependencies
# on external imports.

# NOTE(russellb) If you update these lists, please also update
# doc/source/admin/ovn/features.rst and the current release note.
ML2_SUPPORTED_API_EXTENSIONS_OVN_L3 = [
    l3.ALIAS,
    extraroute.ALIAS,
    l3_ext_gw_mode.ALIAS,
    fip_pf_detail.ALIAS,
    fip_port_details.ALIAS,
    floatingip_pools.ALIAS,
    pagination.ALIAS,
    'qos-fip',
    qos_gateway_ip.ALIAS,
    sorting.ALIAS,
    project_id.ALIAS,
    dns.ALIAS,
    dns_domain_keywords.ALIAS,
    dns_domain_ports.ALIAS,
    subnet_dns_publish_fixed_ip.ALIAS,
    agent_def.ALIAS,
    az_def.ALIAS,
    raz_def.ALIAS,
]
ML2_SUPPORTED_API_EXTENSIONS = [
    address_group.ALIAS,
    address_scope.ALIAS,
    agent_def.ALIAS,
    allowedaddresspairs.ALIAS,
    auto_allocated_topology.ALIAS,
    az_def.ALIAS,
    portbindings.ALIAS,
    pbe_ext.ALIAS,
    default_subnetpools.ALIAS,
    dhcpagentscheduler.ALIAS,
    dns.ALIAS,
    external_net.ALIAS,
    extra_dhcp_opt.ALIAS,
    filter_validation.ALIAS,
    multiprovidernet.ALIAS,
    network_mtu.ALIAS,
    network_mtu_writable.ALIAS,
    network_availability_zone.ALIAS,
    network_ip_availability.ALIAS,
    port_device_profile.ALIAS,
    port_mac_address_regenerate.ALIAS,
    port_numa_affinity_policy.ALIAS,
    port_security.ALIAS,
    provider_net.ALIAS,
    port_resource_request.ALIAS,
    qos.ALIAS,
    qos_bw_limit_direction.ALIAS,
    qos_default.ALIAS,
    qos_rule_type_details.ALIAS,
    qos_rule_type_filter.ALIAS,
    qos_rules_alias.ALIAS,
    'quotas',
    quota_check_limit.ALIAS,
    quotasv2_detail.ALIAS,
    rbac_address_scope.ALIAS,
    'rbac-policies',
    rbac_security_groups.ALIAS,
    'standard-attr-revisions',
    'security-group',
    security_groups_normalized_cidr.ALIAS,
    security_groups_remote_address_group.ALIAS,
    security_groups_shared_filtering.ALIAS,
    stateful_security_group.ALIAS,
    'standard-attr-description',
    constants.SUBNET_ALLOCATION_EXT_ALIAS,
    'standard-attr-tag',
    'standard-attr-timestamp',
    subnet_service_types.ALIAS,
    trunk.ALIAS,
    seg_def.ALIAS,
    expose_port_forwarding_in_fip.ALIAS,
    fip_pf_description.ALIAS,
    fip_pf_port_range.ALIAS,
    floating_ip_port_forwarding.ALIAS,
    vlantransparent.ALIAS,
    logging.ALIAS,
    vpn.ALIAS,
    vpn_endpoint_groups.ALIAS,
    bgp.ALIAS,
    bgp_4byte_asn.ALIAS,
    bgp_dragentscheduler.ALIAS,
    uplink_status_propagation.ALIAS,
]
