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

from neutron_lib.api.definitions import address_scope
from neutron_lib.api.definitions import agent as agent_def
from neutron_lib.api.definitions import allowedaddresspairs
from neutron_lib.api.definitions import auto_allocated_topology
from neutron_lib.api.definitions import availability_zone as az_def
from neutron_lib.api.definitions import default_subnetpools
from neutron_lib.api.definitions import dns
from neutron_lib.api.definitions import expose_port_forwarding_in_fip
from neutron_lib.api.definitions import external_net
from neutron_lib.api.definitions import extra_dhcp_opt
from neutron_lib.api.definitions import extraroute
from neutron_lib.api.definitions import filter_validation
from neutron_lib.api.definitions import fip_pf_description
from neutron_lib.api.definitions import fip_port_details
from neutron_lib.api.definitions import floating_ip_port_forwarding
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
from neutron_lib.api.definitions import port_numa_affinity_policy
from neutron_lib.api.definitions import port_resource_request
from neutron_lib.api.definitions import port_security
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import project_id
from neutron_lib.api.definitions import provider_net
from neutron_lib.api.definitions import qos
from neutron_lib.api.definitions import qos_bw_limit_direction
from neutron_lib.api.definitions import qos_default
from neutron_lib.api.definitions import qos_rule_type_details
from neutron_lib.api.definitions import qos_rules_alias
from neutron_lib.api.definitions import rbac_address_scope
from neutron_lib.api.definitions import router_availability_zone as raz_def
from neutron_lib.api.definitions import security_groups_normalized_cidr
from neutron_lib.api.definitions import security_groups_remote_address_group
from neutron_lib.api.definitions import segment as seg_def
from neutron_lib.api.definitions import sorting
from neutron_lib.api.definitions import trunk
from neutron_lib.api.definitions import vlantransparent
from neutron_lib import constants

# NOTE(russellb) This remains in its own file (vs constants.py) because we want
# to be able to easily import it and export the info without any dependencies
# on external imports.

# NOTE(russellb) If you update these lists, please also update
# doc/source/admin/ovn/features.rst and the current release note.
ML2_SUPPORTED_API_EXTENSIONS_OVN_L3 = [
    l3.ALIAS,
    extraroute.ALIAS,
    l3_ext_gw_mode.ALIAS,
    fip_port_details.ALIAS,
    pagination.ALIAS,
    'qos-fip',
    sorting.ALIAS,
    project_id.ALIAS,
    dns.ALIAS,
    agent_def.ALIAS,
    az_def.ALIAS,
    raz_def.ALIAS,
]
ML2_SUPPORTED_API_EXTENSIONS = [
    address_scope.ALIAS,
    agent_def.ALIAS,
    allowedaddresspairs.ALIAS,
    auto_allocated_topology.ALIAS,
    portbindings.ALIAS,
    default_subnetpools.ALIAS,
    external_net.ALIAS,
    extra_dhcp_opt.ALIAS,
    filter_validation.ALIAS,
    multiprovidernet.ALIAS,
    network_mtu.ALIAS,
    network_mtu_writable.ALIAS,
    network_availability_zone.ALIAS,
    network_ip_availability.ALIAS,
    port_device_profile.ALIAS,
    port_numa_affinity_policy.ALIAS,
    port_security.ALIAS,
    provider_net.ALIAS,
    port_resource_request.ALIAS,
    qos.ALIAS,
    qos_bw_limit_direction.ALIAS,
    qos_default.ALIAS,
    qos_rule_type_details.ALIAS,
    qos_rules_alias.ALIAS,
    'quotas',
    rbac_address_scope.ALIAS,
    'rbac-policies',
    'standard-attr-revisions',
    'security-group',
    security_groups_normalized_cidr.ALIAS,
    security_groups_remote_address_group.ALIAS,
    'standard-attr-description',
    constants.SUBNET_ALLOCATION_EXT_ALIAS,
    'standard-attr-tag',
    'standard-attr-timestamp',
    trunk.ALIAS,
    'quota_details',
    seg_def.ALIAS,
    expose_port_forwarding_in_fip.ALIAS,
    fip_pf_description.ALIAS,
    floating_ip_port_forwarding.ALIAS,
    vlantransparent.ALIAS,
    logging.ALIAS,
]
