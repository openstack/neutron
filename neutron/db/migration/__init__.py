# Copyright 2012 New Dream Network, LLC (DreamHost)
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
# @author: Mark McClain, DreamHost

from alembic import op
import sqlalchemy as sa

OVS_PLUGIN = ('neutron.plugins.openvswitch.ovs_neutron_plugin'
              '.OVSNeutronPluginV2')
CISCO_PLUGIN = 'neutron.plugins.cisco.network_plugin.PluginV2'


def should_run(active_plugins, migrate_plugins):
    if '*' in migrate_plugins:
        return True
    else:
        if (CISCO_PLUGIN not in migrate_plugins and
                OVS_PLUGIN in migrate_plugins):
            migrate_plugins.append(CISCO_PLUGIN)
        return set(active_plugins) & set(migrate_plugins)


def alter_enum(table, column, enum_type, nullable):
    bind = op.get_bind()
    engine = bind.engine
    if engine.name == 'postgresql':
        values = {'table': table,
                  'column': column,
                  'name': enum_type.name}
        op.execute("ALTER TYPE %(name)s RENAME TO old_%(name)s" % values)
        enum_type.create(bind, checkfirst=False)
        op.execute("ALTER TABLE %(table)s RENAME COLUMN %(column)s TO "
                   "old_%(column)s" % values)
        op.add_column(table, sa.Column(column, enum_type, nullable=nullable))
        op.execute("UPDATE %(table)s SET %(column)s = "
                   "old_%(column)s::text::%(name)s" % values)
        op.execute("ALTER TABLE %(table)s DROP COLUMN old_%(column)s" % values)
        op.execute("DROP TYPE old_%(name)s" % values)
    else:
        op.alter_column(table, column, type_=enum_type,
                        existing_nullable=nullable)


def create_table_if_not_exist_psql(table_name, values):
    if op.get_bind().engine.dialect.server_version_info < (9, 1, 0):
        op.execute("CREATE LANGUAGE plpgsql")
    op.execute("CREATE OR REPLACE FUNCTION execute(TEXT) RETURNS VOID AS $$"
               "BEGIN EXECUTE $1; END;"
               "$$ LANGUAGE plpgsql STRICT;")
    op.execute("CREATE OR REPLACE FUNCTION table_exist(TEXT) RETURNS bool as "
               "$$ SELECT exists(select 1 from pg_class where relname=$1);"
               "$$ language sql STRICT;")
    op.execute("SELECT execute($$CREATE TABLE %(name)s %(columns)s $$) "
               "WHERE NOT table_exist(%(name)r);" %
               {'name': table_name,
                'columns': values})