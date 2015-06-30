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

TABLES = (FWAAS_TABLES + LBAAS_TABLES + VPNAAS_TABLES)
