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
                 'ipsec_site_connections', 'ikepolicies']

# Neutron-lbaas is retired, but we need to keep this for the models until
# we decide to remove the tables.
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
          REPO_BROCADE_TABLES +
          REPO_BIGSWITCH_TABLES +
          REPO_NUAGE_TABLES)
