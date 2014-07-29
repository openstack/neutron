# Copyright (c) 2014 Red Hat, Inc.
# All Rights Reserved.
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

"""
This script will migrate the database of an openvswitch or linuxbridge
plugin so that it can be used with the ml2 plugin.

Known Limitations:

   - THIS SCRIPT IS DESTRUCTIVE!  Make sure to backup your
   Neutron database before running this script, in case anything goes
   wrong.

   - It will be necessary to upgrade the database to the target release
   via neutron-db-manage before attempting to migrate to ml2.
   Initially, only the icehouse release is supported.

   - This script does not automate configuration migration.

Example usage:

  python -m neutron.db.migration.migrate_to_ml2 openvswitch \
      mysql://login:pass@127.0.0.1/neutron

Note that migration of tunneling state will only be attemped if the
--tunnel-type parameter is provided.

To manually test migration from ovs to ml2 with devstack:

 - stack with Q_PLUGIN=openvswitch
 - boot an instance and validate connectivity
 - stop the neutron service and all agents
 - run the neutron-migrate-to-ml2 script
 - update /etc/neutron/neutron.conf as follows:

   core_plugin = neutron.plugins.ml2.plugin.Ml2Plugin

 - Create /etc/neutron/plugins/ml2/ml2_conf.ini and ensure that:
    - ml2.mechanism_drivers includes 'openvswitch'
    - ovs.local_ip is set correctly
    - database.connection is set correctly
 - Start the neutron service with the ml2 config file created in
   the previous step in place of the openvswitch config file
 - Start all the agents
 - verify that the booted instance still has connectivity
 - boot a second instance and validate connectivity
"""

import argparse

import sqlalchemy as sa

from neutron.extensions import portbindings
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2.drivers import type_vxlan


# Migration targets
LINUXBRIDGE = 'linuxbridge'
OPENVSWITCH = 'openvswitch'

# Releases
ICEHOUSE = 'icehouse'


SUPPORTED_SCHEMA_VERSIONS = [ICEHOUSE]


def check_db_schema_version(engine, metadata):
    """Check that current version of the db schema is supported."""
    version_table = sa.Table(
        'alembic_version', metadata, autoload=True, autoload_with=engine)
    versions = [v[0] for v in engine.execute(version_table.select())]
    if not versions:
        raise ValueError(_("Missing version in alembic_versions table"))
    elif len(versions) > 1:
        raise ValueError(_("Multiple versions in alembic_versions table: %s")
                         % versions)
    current_version = versions[0]
    if current_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise SystemError(_("Unsupported database schema %(current)s. "
                            "Please migrate your database to one of following "
                            "versions: %(supported)s")
                          % {'current': current_version,
                             'supported': ', '.join(SUPPORTED_SCHEMA_VERSIONS)}
                          )


# Duplicated from neutron.plugins.linuxbridge.common.constants to
# avoid having any dependency on the linuxbridge plugin being
# installed.
def interpret_vlan_id(vlan_id):
    """Return (network_type, segmentation_id) tuple for encoded vlan_id."""
    FLAT_VLAN_ID = -1
    LOCAL_VLAN_ID = -2
    if vlan_id == LOCAL_VLAN_ID:
        return (p_const.TYPE_LOCAL, None)
    elif vlan_id == FLAT_VLAN_ID:
        return (p_const.TYPE_FLAT, None)
    else:
        return (p_const.TYPE_VLAN, vlan_id)


class BaseMigrateToMl2_Icehouse(object):

    def __init__(self, vif_type, driver_type, segment_table_name,
                 vlan_allocation_table_name, old_tables):
        self.vif_type = vif_type
        self.driver_type = driver_type
        self.segment_table_name = segment_table_name
        self.vlan_allocation_table_name = vlan_allocation_table_name
        self.old_tables = old_tables

    def __call__(self, connection_url, save_tables=False, tunnel_type=None,
                 vxlan_udp_port=None):
        engine = sa.create_engine(connection_url)
        metadata = sa.MetaData()
        check_db_schema_version(engine, metadata)

        self.define_ml2_tables(metadata)

        # Autoload the ports table to ensure that foreign keys to it and
        # the network table can be created for the new tables.
        sa.Table('ports', metadata, autoload=True, autoload_with=engine)
        metadata.create_all(engine)

        self.migrate_network_segments(engine, metadata)
        if tunnel_type:
            self.migrate_tunnels(engine, tunnel_type, vxlan_udp_port)
        self.migrate_vlan_allocations(engine)
        self.migrate_port_bindings(engine, metadata)

        self.drop_old_tables(engine, save_tables)

    def migrate_segment_dict(self, binding):
        binding['id'] = uuidutils.generate_uuid()

    def migrate_network_segments(self, engine, metadata):
        # Migrating network segments requires loading the data to python
        # so that a uuid can be generated for each segment.
        source_table = sa.Table(self.segment_table_name, metadata,
                                autoload=True, autoload_with=engine)
        source_segments = engine.execute(source_table.select())
        ml2_segments = [dict(x) for x in source_segments]
        for segment in ml2_segments:
            self.migrate_segment_dict(segment)
        if ml2_segments:
            ml2_network_segments = metadata.tables['ml2_network_segments']
            engine.execute(ml2_network_segments.insert(), ml2_segments)

    def migrate_tunnels(self, engine, tunnel_type, vxlan_udp_port=None):
        """Override this method to perform plugin-specific tunnel migration."""
        pass

    def migrate_vlan_allocations(self, engine):
        engine.execute(("""
          INSERT INTO ml2_vlan_allocations
            SELECT physical_network, vlan_id, allocated
              FROM %(source_table)s
              WHERE allocated = 1
        """) % {'source_table': self.vlan_allocation_table_name})

    def get_port_segment_map(self, engine):
        """Retrieve a mapping of port id to segment id.

        The monolithic plugins only support a single segment per
        network, so the segment id can be uniquely identified by
        the network associated with a given port.

        """
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

    def migrate_port_bindings(self, engine, metadata):
        port_segment_map = self.get_port_segment_map(engine)

        port_binding_ports = sa.Table('portbindingports', metadata,
                                      autoload=True, autoload_with=engine)
        source_bindings = engine.execute(port_binding_ports.select())
        ml2_bindings = [dict(x) for x in source_bindings]
        for binding in ml2_bindings:
            binding['vif_type'] = self.vif_type
            binding['driver'] = self.driver_type
            segment = port_segment_map.get(binding['port_id'])
            if segment:
                binding['segment'] = segment
        if ml2_bindings:
            ml2_port_bindings = metadata.tables['ml2_port_bindings']
            engine.execute(ml2_port_bindings.insert(), ml2_bindings)

    def drop_old_tables(self, engine, save_tables=False):
        if save_tables:
            return
        old_tables = self.old_tables + [self.vlan_allocation_table_name,
                                        self.segment_table_name]
        for table_name in old_tables:
            engine.execute('DROP TABLE %s' % table_name)

    def define_ml2_tables(self, metadata):

        sa.Table(
            'arista_provisioned_nets', metadata,
            sa.Column('tenant_id', sa.String(length=255), nullable=True),
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('network_id', sa.String(length=36), nullable=True),
            sa.Column('segmentation_id', sa.Integer(),
                      autoincrement=False, nullable=True),
            sa.PrimaryKeyConstraint('id'),
        )

        sa.Table(
            'arista_provisioned_vms', metadata,
            sa.Column('tenant_id', sa.String(length=255), nullable=True),
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('vm_id', sa.String(length=255), nullable=True),
            sa.Column('host_id', sa.String(length=255), nullable=True),
            sa.Column('port_id', sa.String(length=36), nullable=True),
            sa.Column('network_id', sa.String(length=36), nullable=True),
            sa.PrimaryKeyConstraint('id'),
        )

        sa.Table(
            'arista_provisioned_tenants', metadata,
            sa.Column('tenant_id', sa.String(length=255), nullable=True),
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.PrimaryKeyConstraint('id'),
        )

        sa.Table(
            'cisco_ml2_nexusport_bindings', metadata,
            sa.Column('binding_id', sa.Integer(), nullable=False),
            sa.Column('port_id', sa.String(length=255), nullable=True),
            sa.Column('vlan_id', sa.Integer(), autoincrement=False,
                      nullable=False),
            sa.Column('switch_ip', sa.String(length=255), nullable=True),
            sa.Column('instance_id', sa.String(length=255), nullable=True),
            sa.PrimaryKeyConstraint('binding_id'),
        )

        sa.Table(
            'cisco_ml2_credentials', metadata,
            sa.Column('credential_id', sa.String(length=255), nullable=True),
            sa.Column('tenant_id', sa.String(length=255), nullable=False),
            sa.Column('credential_name', sa.String(length=255),
                      nullable=False),
            sa.Column('user_name', sa.String(length=255), nullable=True),
            sa.Column('password', sa.String(length=255), nullable=True),
            sa.PrimaryKeyConstraint('tenant_id', 'credential_name'),
        )

        sa.Table(
            'ml2_flat_allocations', metadata,
            sa.Column('physical_network', sa.String(length=64),
                      nullable=False),
            sa.PrimaryKeyConstraint('physical_network'),
        )

        sa.Table(
            'ml2_gre_allocations', metadata,
            sa.Column('gre_id', sa.Integer, nullable=False,
                      autoincrement=False),
            sa.Column('allocated', sa.Boolean, nullable=False),
            sa.PrimaryKeyConstraint('gre_id'),
        )

        sa.Table(
            'ml2_gre_endpoints', metadata,
            sa.Column('ip_address', sa.String(length=64)),
            sa.PrimaryKeyConstraint('ip_address'),
        )

        sa.Table(
            'ml2_network_segments', metadata,
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('network_id', sa.String(length=36), nullable=False),
            sa.Column('network_type', sa.String(length=32), nullable=False),
            sa.Column('physical_network', sa.String(length=64), nullable=True),
            sa.Column('segmentation_id', sa.Integer(), nullable=True),
            sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                    ondelete='CASCADE'),
            sa.PrimaryKeyConstraint('id'),
        )

        sa.Table(
            'ml2_port_bindings', metadata,
            sa.Column('port_id', sa.String(length=36), nullable=False),
            sa.Column('host', sa.String(length=255), nullable=False),
            sa.Column('vif_type', sa.String(length=64), nullable=False),
            sa.Column('driver', sa.String(length=64), nullable=True),
            sa.Column('segment', sa.String(length=36), nullable=True),
            sa.Column('vnic_type', sa.String(length=64), nullable=False,
                      server_default='normal'),
            sa.Column('vif_details', sa.String(4095), nullable=False,
                      server_default=''),
            sa.Column('profile', sa.String(4095), nullable=False,
                      server_default=''),
            sa.ForeignKeyConstraint(['port_id'], ['ports.id'],
                                    ondelete='CASCADE'),
            sa.ForeignKeyConstraint(['segment'], ['ml2_network_segments.id'],
                                    ondelete='SET NULL'),
            sa.PrimaryKeyConstraint('port_id'),
        )

        sa.Table(
            'ml2_vlan_allocations', metadata,
            sa.Column('physical_network', sa.String(length=64),
                      nullable=False),
            sa.Column('vlan_id', sa.Integer(), autoincrement=False,
                      nullable=False),
            sa.Column('allocated', sa.Boolean(), autoincrement=False,
                      nullable=False),
            sa.PrimaryKeyConstraint('physical_network', 'vlan_id'),
        )

        sa.Table(
            'ml2_vxlan_allocations', metadata,
            sa.Column('vxlan_vni', sa.Integer, nullable=False,
                      autoincrement=False),
            sa.Column('allocated', sa.Boolean, nullable=False),
            sa.PrimaryKeyConstraint('vxlan_vni'),
        )

        sa.Table(
            'ml2_vxlan_endpoints', metadata,
            sa.Column('ip_address', sa.String(length=64)),
            sa.Column('udp_port', sa.Integer(), nullable=False,
                      autoincrement=False),
            sa.PrimaryKeyConstraint('ip_address', 'udp_port'),
        )


class MigrateLinuxBridgeToMl2_Icehouse(BaseMigrateToMl2_Icehouse):

    def __init__(self):
        super(MigrateLinuxBridgeToMl2_Icehouse, self).__init__(
            vif_type=portbindings.VIF_TYPE_BRIDGE,
            driver_type=LINUXBRIDGE,
            segment_table_name='network_bindings',
            vlan_allocation_table_name='network_states',
            old_tables=['portbindingports'])

    def migrate_segment_dict(self, binding):
        super(MigrateLinuxBridgeToMl2_Icehouse, self).migrate_segment_dict(
            binding)
        vlan_id = binding.pop('vlan_id')
        network_type, segmentation_id = interpret_vlan_id(vlan_id)
        binding['network_type'] = network_type
        binding['segmentation_id'] = segmentation_id


class MigrateOpenvswitchToMl2_Icehouse(BaseMigrateToMl2_Icehouse):

    def __init__(self):
        super(MigrateOpenvswitchToMl2_Icehouse, self).__init__(
            vif_type=portbindings.VIF_TYPE_OVS,
            driver_type=OPENVSWITCH,
            segment_table_name='ovs_network_bindings',
            vlan_allocation_table_name='ovs_vlan_allocations',
            old_tables=[
                'ovs_tunnel_allocations',
                'ovs_tunnel_endpoints',
                'portbindingports',
            ])

    def migrate_tunnels(self, engine, tunnel_type, vxlan_udp_port=None):
        if tunnel_type == p_const.TYPE_GRE:
            engine.execute("""
              INSERT INTO ml2_gre_allocations
                SELECT tunnel_id as gre_id, allocated
                  FROM ovs_tunnel_allocations
                  WHERE allocated = 1
            """)
            engine.execute("""
              INSERT INTO ml2_gre_endpoints
                SELECT ip_address
                  FROM ovs_tunnel_endpoints
            """)
        elif tunnel_type == p_const.TYPE_VXLAN:
            if not vxlan_udp_port:
                vxlan_udp_port = type_vxlan.VXLAN_UDP_PORT
            engine.execute("""
              INSERT INTO ml2_vxlan_allocations
                SELECT tunnel_id as vxlan_vni, allocated
                  FROM ovs_tunnel_allocations
                  WHERE allocated = 1
            """)
            engine.execute(sa.text("""
              INSERT INTO ml2_vxlan_endpoints
                SELECT ip_address, :udp_port as udp_port
                  FROM ovs_tunnel_endpoints
            """), udp_port=vxlan_udp_port)
        else:
            raise ValueError(_('Unknown tunnel type: %s') % tunnel_type)


migrate_map = {
    ICEHOUSE: {
        OPENVSWITCH: MigrateOpenvswitchToMl2_Icehouse,
        LINUXBRIDGE: MigrateLinuxBridgeToMl2_Icehouse,
    },
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('plugin', choices=[OPENVSWITCH, LINUXBRIDGE],
                        help=_('The plugin type whose database will be '
                               'migrated'))
    parser.add_argument('connection',
                        help=_('The connection url for the target db'))
    parser.add_argument('--tunnel-type', choices=[p_const.TYPE_GRE,
                                                  p_const.TYPE_VXLAN],
                        help=_('The %s tunnel type to migrate from') %
                        OPENVSWITCH)
    parser.add_argument('--vxlan-udp-port', default=None, type=int,
                        help=_('The UDP port to use for VXLAN tunnels.'))
    parser.add_argument('--release', default=ICEHOUSE, choices=[ICEHOUSE])
    parser.add_argument('--save-tables', default=False, action='store_true',
                        help=_("Retain the old plugin's tables"))
    #TODO(marun) Provide a verbose option
    args = parser.parse_args()

    if args.plugin == LINUXBRIDGE and (args.tunnel_type or
                                       args.vxlan_udp_port):
        msg = _('Tunnel args (tunnel-type and vxlan-udp-port) are not valid '
                'for the %s plugin')
        parser.error(msg % LINUXBRIDGE)

    try:
        migrate_func = migrate_map[args.release][args.plugin]()
    except KeyError:
        msg = _('Support for migrating %(plugin)s for release '
                '%(release)s is not yet implemented')
        parser.error(msg % {'plugin': args.plugin, 'release': args.release})
    else:
        migrate_func(args.connection, args.save_tables, args.tunnel_type,
                     args.vxlan_udp_port)


if __name__ == '__main__':
    main()
