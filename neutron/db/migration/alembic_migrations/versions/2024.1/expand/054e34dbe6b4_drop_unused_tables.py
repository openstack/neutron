# Copyright 2023 OpenStack Foundation
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

import itertools

from alembic import op
from oslo_db import exception as os_db_exc
import sqlalchemy as sa
from sqlalchemy import exc

from neutron._i18n import _


# Drop unused tables
#
# Revision ID: 054e34dbe6b4
# Revises: 89c58a70ceba
# Create Date: 2023-10-05 16:02:03.812939

# revision identifiers, used by Alembic.
revision = '054e34dbe6b4'
down_revision = '89c58a70ceba'

# Ordered tables to delete first the tables with foreign keys references.
REPO_CISCO_TABLES = [
    'cisco_ml2_apic_contracts',
    'cisco_ml2_apic_names',
    'cisco_ml2_apic_host_links',
    'cisco_ml2_n1kv_policy_profiles',
    'cisco_ml2_n1kv_port_bindings',
    'cisco_ml2_n1kv_network_bindings',
    'cisco_ml2_n1kv_vxlan_allocations',
    'cisco_ml2_n1kv_vlan_allocations',
    'cisco_ml2_n1kv_profile_bindings',
    'cisco_ml2_nexusport_bindings',
    'cisco_ml2_nexus_nve',
    'ml2_nexus_vxlan_mcast_groups',
    'ml2_ucsm_port_profiles',
    'cisco_port_mappings',
    'cisco_router_mappings',
    'cisco_hosting_devices',
    'cisco_ml2_n1kv_network_profiles',
    'ml2_nexus_vxlan_allocations',
    'cisco_network_profiles',
    'cisco_policy_profiles',
]

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
    'portqueuemappings',
    'networkqueuemappings',
    'qosqueues',
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

REPO_BROCADE_TABLES = [
    'brocadeports',
    'brocadenetworks',
    'ml2_brocadeports',
    'ml2_brocadenetworks',
]

REPO_NUAGE_TABLES = [
    'nuage_net_partition_router_mapping',
    'nuage_provider_net_bindings',
    'nuage_subnet_l2dom_mapping',
    'nuage_net_partitions',
]

TABLES_TO_DROP = itertools.chain(
    REPO_CISCO_TABLES,
    REPO_VMWARE_TABLES,
    REPO_BROCADE_TABLES,
    REPO_NUAGE_TABLES,
    ['cisco_csr_identifier_map']
)


def upgrade():
    inspector = sa.inspect(op.get_bind())
    db_tables = inspector.get_table_names()
    tables_to_drop = list(TABLES_TO_DROP)
    while tables_to_drop:
        # Tables that have not been dropped in this iteration.
        missed_tables = []
        errors = []
        for table in (t for t in tables_to_drop if t in db_tables):
            try:
                op.drop_table(table)
            except (exc.OperationalError, os_db_exc.DBError) as _exc:
                # If the table cannot be deleted is because some reference
                # from other table that should be deleted first.
                missed_tables.append(table)
                errors.append(str(_exc))

        if len(missed_tables) == len(tables_to_drop):
            raise Exception(_('The following tables have not been dropped '
                              'from the Neutron database: %(missed_tables)s.\n'
                              'List of errors: %(errors)s') %
                              {'missed_tables': ', '.join(missed_tables),
                               'errors': '\n'.join(errors)}
                              )

        tables_to_drop = missed_tables


def expand_drop_exceptions():
    """Support dropping TABLES_TO_DROP"""

    return {
        sa.Table: list(TABLES_TO_DROP)
    }
