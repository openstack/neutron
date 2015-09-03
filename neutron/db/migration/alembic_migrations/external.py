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
                'embrane_pool_port', 'poolmonitorassociations']

FWAAS_TABLES = ['firewall_rules', 'firewalls', 'firewall_policies']

# Arista ML2 driver Models moved to openstack/networking-arista
REPO_ARISTA_TABLES = [
    'arista_provisioned_nets',
    'arista_provisioned_vms',
    'arista_provisioned_tenants',
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

# NEC models moved to stackforge/networking-nec
REPO_NEC_TABLES = [
    'ofcnetworkmappings',
    'ofcportmappings',
    'ofcroutermappings',
    'ofcfiltermappings',
    'ofctenantmappings',
    'portinfos',
    'routerproviders',
    'packetfilters',
]

TABLES = (FWAAS_TABLES + LBAAS_TABLES + VPNAAS_TABLES +
          REPO_ARISTA_TABLES +
          REPO_CISCO_TABLES +
          REPO_VMWARE_TABLES +
          REPO_NEC_TABLES)
