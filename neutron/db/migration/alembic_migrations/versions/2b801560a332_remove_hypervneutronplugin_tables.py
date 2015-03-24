# Copyright 2015 OpenStack Foundation
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

"""Remove Hyper-V Neutron Plugin

Migrates the contents of the tables 'hyperv_vlan_allocations' and
'hyperv_network_bindings' to 'ml2_vlan_allocations' and 'ml2_network_segments'
respectively, and then removes the tables.

Thse tables are used by HyperVNeutronPlugin, which will be removed.

Revision ID: 2b801560a332
Revises: 4119216b7365
Create Date: 2015-02-12 09:23:40.346104

"""

# revision identifiers, used by Alembic.
revision = '2b801560a332'
down_revision = '2d2a8a565438'

from alembic import op
from sqlalchemy.sql import expression as sa_expr

from neutron.extensions import portbindings
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants as p_const

FLAT_VLAN_ID = -1
LOCAL_VLAN_ID = -2
HYPERV = 'hyperv'


# Duplicated from neutron.plugins.linuxbridge.common.constants to
# avoid being dependent on it, as it will eventually be removed.
def _interpret_vlan_id(vlan_id):
    """Return (network_type, segmentation_id) tuple for encoded vlan_id."""
    if vlan_id == LOCAL_VLAN_ID:
        return (p_const.TYPE_LOCAL, None)
    elif vlan_id == FLAT_VLAN_ID:
        return (p_const.TYPE_FLAT, None)
    else:
        return (p_const.TYPE_VLAN, vlan_id)


def _migrate_segment_dict(binding):
    binding['id'] = uuidutils.generate_uuid()
    vlan_id = binding.pop('segmentation_id')
    network_type, segmentation_id = _interpret_vlan_id(vlan_id)
    binding['network_type'] = network_type
    binding['segmentation_id'] = segmentation_id


def _migrate_vlan_allocations():
    # Code similar to migrate_to_ml2.BaseMigrateToMl2.migrate_vlan_allocations
    if op.get_bind().engine.name == 'ibm_db_sa':
        op.execute('INSERT INTO ml2_vlan_allocations '
                   'SELECT physical_network, vlan_id, allocated '
                   'FROM hyperv_vlan_allocations '
                   'WHERE allocated = 1')
    else:
        op.execute('INSERT INTO ml2_vlan_allocations '
                   'SELECT physical_network, vlan_id, allocated '
                   'FROM hyperv_vlan_allocations '
                   'WHERE allocated = TRUE')


def _migrate_network_segments(engine):
    # Code similar to migrate_to_ml2.BaseMigrateToMl2.migrate_network_segments
    source_table = sa_expr.table('hyperv_network_bindings')
    source_segments = engine.execute(
        sa_expr.select(['*'], from_obj=source_table))
    ml2_segments = [dict(x) for x in source_segments]
    for segment in ml2_segments:
        _migrate_segment_dict(segment)

    if ml2_segments:
        ml2_network_segments = sa_expr.table('ml2_network_segments')
        op.execute(ml2_network_segments.insert(), ml2_segments)


def _get_port_segment_map(engine):
    # Code from migrate_to_ml2.BaseMigrateToMl2.get_port_segment_map
    port_segments = engine.execute("""
        SELECT ports_network.port_id, ml2_network_segments.id AS segment_id
          FROM ml2_network_segments, (
            SELECT portbindingports.port_id, ports.network_id
              FROM portbindingports, ports
              WHERE portbindingports.port_id = ports.id
          ) AS ports_network
          WHERE ml2_network_segments.network_id = ports_network.network_id
    """)
    return dict(x for x in port_segments)


def _migrate_port_bindings(engine):
    # Code similar to migrate_to_ml2.BaseMigrateToMl2.migrate_port_bindings
    port_segment_map = _get_port_segment_map(engine)
    port_binding_ports = sa_expr.table('portbindingports')
    source_bindings = engine.execute(
        sa_expr.select(['*'], from_obj=port_binding_ports))
    ml2_bindings = [dict(x) for x in source_bindings]
    for binding in ml2_bindings:
        binding['vif_type'] = portbindings.VIF_TYPE_HYPERV
        binding['driver'] = HYPERV
        segment = port_segment_map.get(binding['port_id'])
        if segment:
            binding['segment'] = segment
    if ml2_bindings:
        ml2_port_bindings = sa_expr.table('ml2_port_bindings')
        op.execute(ml2_port_bindings.insert(), ml2_bindings)


def upgrade():
    bind = op.get_bind()

    _migrate_vlan_allocations()
    _migrate_network_segments(bind)
    _migrate_port_bindings(bind)

    op.drop_table('hyperv_vlan_allocations')
    op.drop_table('hyperv_network_bindings')
