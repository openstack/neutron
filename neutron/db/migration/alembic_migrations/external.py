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


# These tables are in the neutron database, but their models have moved
# to separate repositories. We skip the migration checks for these tables.

VPNAAS_TABLES = ['vpnservices', 'ipsecpolicies', 'ipsecpeercidrs',
                 'ipsec_site_connections', 'cisco_csr_identifier_map',
                 'ikepolicies']

LBAAS_TABLES = ['vips', 'sessionpersistences', 'pools', 'healthmonitors',
                'poolstatisticss', 'members', 'poolloadbalanceragentbindings',
                'poolmonitorassociations']

FWAAS_TABLES = ['firewall_rules', 'firewalls', 'firewall_policies']

# Arista ML2 driver Models moved to openstack/networking-arista
REPO_ARISTA_TABLES = [
    'arista_provisioned_nets',
    'arista_provisioned_vms',
    'arista_provisioned_tenants',
]

# BGP models in openstack/neutron-dynamic-routing
REPO_NEUTRON_DYNAMIC_ROUTING_TABLES = [
    'bgp_speakers',
    'bgp_peers',
    'bgp_speaker_network_bindings',
    'bgp_speaker_peer_bindings',
    'bgp_speaker_dragent_bindings',
]

# Models moved to openstack/networking-cisco
REPO_CISCO_TABLES = [
    'cisco_ml2_apic_contracts',
    'cisco_ml2_apic_names',
    'cisco_ml2_apic_host_links',
    'cisco_ml2_n1kv_policy_profiles',
    'cisco_ml2_n1kv_network_profiles',
    'cisco_ml2_n1kv_port_bindings',
    'cisco_ml2_n1kv_network_bindings',
    'cisco_ml2_n1kv_vxlan_allocations',
    'cisco_ml2_n1kv_vlan_allocations',
    'cisco_ml2_n1kv_profile_bindings',
    'cisco_ml2_nexusport_bindings',
    'cisco_ml2_nexus_nve',
    'ml2_nexus_vxlan_allocations',
    'ml2_nexus_vxlan_mcast_groups',
    'ml2_ucsm_port_profiles',
    'cisco_hosting_devices',
    'cisco_port_mappings',
    'cisco_router_mappings',
]

# VMware-NSX models moved to openstack/vmware-nsx
REPO_VMWARE_TABLES = [
    'tz_network_bindings',
    'neutron_nsx_network_mappings',
    'neutron_nsx_security_group_mappings',
    'neutron_nsx_port_mappings',
    'neutron_nsx_router_mappings',
    'multi_provider_networks',
    'networkconnections',
    'networkgatewaydevicereferences',
    'networkgatewaydevices',
    'networkgateways',
    'maclearningstates',
    'qosqueues',
    'portqueuemappings',
    'networkqueuemappings',
    'lsn_port',
    'lsn',
    'nsxv_router_bindings',
    'nsxv_edge_vnic_bindings',
    'nsxv_edge_dhcp_static_bindings',
    'nsxv_internal_networks',
    'nsxv_internal_edges',
    'nsxv_security_group_section_mappings',
    'nsxv_rule_mappings',
    'nsxv_port_vnic_mappings',
    'nsxv_router_ext_attributes',
    'nsxv_tz_network_bindings',
    'nsxv_port_index_mappings',
    'nsxv_firewall_rule_bindings',
    'nsxv_spoofguard_policy_network_mappings',
    'nsxv_vdr_dhcp_bindings',
    'vcns_router_bindings',
]

# Brocade models are in openstack/networking-brocade
REPO_BROCADE_TABLES = [
    'brocadenetworks',
    'brocadeports',
    'ml2_brocadenetworks',
    'ml2_brocadeports',
]

# BigSwitch models are in openstack/networking-bigswitch
REPO_BIGSWITCH_TABLES = [
    'consistencyhashes',
    'routerrules',
    'nexthops',
]

# Nuage models are in github.com/nuagenetworks/nuage-openstack-neutron
REPO_NUAGE_TABLES = [
    'nuage_net_partitions',
    'nuage_net_partition_router_mapping',
    'nuage_provider_net_bindings',
    'nuage_subnet_l2dom_mapping',
]

TABLES = (FWAAS_TABLES + LBAAS_TABLES + VPNAAS_TABLES +
          REPO_ARISTA_TABLES +
          REPO_NEUTRON_DYNAMIC_ROUTING_TABLES +
          REPO_CISCO_TABLES +
          REPO_VMWARE_TABLES +
          REPO_BROCADE_TABLES +
          REPO_BIGSWITCH_TABLES +
          REPO_NUAGE_TABLES)
