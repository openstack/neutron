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

import contextlib
import functools

from alembic import context
from alembic import op
import sqlalchemy as sa

from neutron._i18n import _

# Neutron milestones for upgrade aliases
LIBERTY = 'liberty'
MITAKA = 'mitaka'
NEWTON = 'newton'
OCATA = 'ocata'
PIKE = 'pike'
QUEENS = 'queens'
ROCKY = 'rocky'
STEIN = 'stein'
TRAIN = 'train'
USSURI = 'ussuri'
VICTORIA = 'victoria'
WALLABY = 'wallaby'
XENA = 'xena'
YOGA = 'yoga'
ZED = 'zed'
RELEASE_2023_1 = '2023.1'
RELEASE_2023_2 = '2023.2'

NEUTRON_MILESTONES = [
    # earlier milestones were not tagged
    LIBERTY,
    MITAKA,
    NEWTON,
    OCATA,
    PIKE,
    QUEENS,
    ROCKY,
    STEIN,
    TRAIN,
    USSURI,
    VICTORIA,
    WALLABY,
    XENA,
    YOGA,
    RELEASE_2023_1,
    RELEASE_2023_2,
    # Do not add the milestone until the end of the release
]


def skip_if_offline(func):
    """Decorator for skipping migrations in offline mode."""
    @functools.wraps(func)
    def decorator(*args, **kwargs):
        if context.is_offline_mode():
            return
        return func(*args, **kwargs)

    return decorator


def raise_if_offline(func):
    """Decorator for raising if a function is called in offline mode."""
    @functools.wraps(func)
    def decorator(*args, **kwargs):
        if context.is_offline_mode():
            raise RuntimeError(_("%s cannot be called while in offline mode") %
                               func.__name__)
        return func(*args, **kwargs)

    return decorator


@raise_if_offline
def schema_has_table(table_name):
    """Check whether the specified table exists in the current schema.

    This method cannot be executed in offline mode.
    """
    insp = sa.inspect(op.get_bind())
    return table_name in insp.get_table_names()


@raise_if_offline
def schema_has_column(table_name, column_name):
    """Check whether the specified column exists in the current schema.

    This method cannot be executed in offline mode.
    """
    insp = sa.inspect(op.get_bind())
    # first check that the table exists
    if not schema_has_table(table_name):
        return
    # check whether column_name exists in table columns
    return column_name in [column['name'] for column in
                           insp.get_columns(table_name)]


@raise_if_offline
def alter_column_if_exists(table_name, column_name, **kwargs):
    """Alter a column only if it exists in the schema."""
    if schema_has_column(table_name, column_name):
        op.alter_column(table_name, column_name, **kwargs)


@raise_if_offline
def drop_table_if_exists(table_name):
    if schema_has_table(table_name):
        op.drop_table(table_name)


@raise_if_offline
def rename_table_if_exists(old_table_name, new_table_name):
    if schema_has_table(old_table_name):
        op.rename_table(old_table_name, new_table_name)


def alter_enum_add_value(table, column, enum, nullable, server_default=None):
    '''If we need to expand Enum values for some column - for PostgreSQL this
    can be done with ALTER TYPE function. For MySQL, it can be done with
    ordinary alembic alter_column function.

    :param table:table name
    :param column: column name
    :param enum: sqlalchemy Enum with updated values
    :param nullable: existing nullable for column.
    :param server_default: existing or new server_default for the column
    '''

    bind = op.get_bind()
    engine = bind.engine
    if engine.name == 'postgresql':
        values = {'name': enum.name,
                  'values': ", ".join("'" + i + "'" for i in enum.enums),
                  'column': column,
                  'table': table,
                  'server_default': server_default}
        if server_default is not None:
            op.execute("ALTER TABLE %(table)s ALTER COLUMN %(column)s"
                       " DROP DEFAULT" % values)
        op.execute("ALTER TYPE %(name)s rename to old_%(name)s" % values)
        op.execute("CREATE TYPE %(name)s AS enum (%(values)s)" % values)
        op.execute("ALTER TABLE %(table)s ALTER COLUMN %(column)s TYPE "
                   "%(name)s USING %(column)s::text::%(name)s " % values)
        if server_default is not None:
            op.execute("ALTER TABLE %(table)s ALTER COLUMN %(column)s"
                       " SET DEFAULT '%(server_default)s'" % values)
        op.execute("DROP TYPE old_%(name)s" % values)
    else:
        op.alter_column(table, column, type_=enum,
                        existing_nullable=nullable,
                        server_default=server_default)


def alter_enum(table, column, enum_type, nullable,
               server_default=None, do_drop=True,
               do_rename=True, do_create=True):
    """Alter a enum type column.
    Set the do_xx parameters only when the modified enum type
    is used by multiple columns. Else don't provide these
    parameters.

    :param server_default: existing or new server_default for the column
    :param do_drop: set to False when modified column is
    not the last one use this enum
    :param do_rename: set to False when modified column is
    not the first one use this enum
    :param do_create: set to False when modified column is
    not the first one use this enum
    """
    bind = op.get_bind()
    engine = bind.engine
    if engine.name == 'postgresql':
        values = {'table': table,
                  'column': column,
                  'name': enum_type.name}
        if do_rename:
            op.execute("ALTER TYPE %(name)s RENAME TO old_%(name)s" % values)
        if do_create:
            enum_type.create(bind, checkfirst=False)
        op.execute("ALTER TABLE %(table)s RENAME COLUMN %(column)s TO "
                   "old_%(column)s" % values)
        op.add_column(table, sa.Column(column, enum_type, nullable=nullable,
                                       server_default=server_default))
        op.execute("UPDATE %(table)s SET %(column)s = "  # nosec
                   "old_%(column)s::text::%(name)s" % values)
        op.execute("ALTER TABLE %(table)s DROP COLUMN old_%(column)s" % values)
        if do_drop:
            op.execute("DROP TYPE old_%(name)s" % values)
    else:
        op.alter_column(table, column, type_=enum_type,
                        existing_nullable=nullable,
                        server_default=server_default)


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


def get_unique_constraints_map(table):
    inspector = sa.inspect(op.get_bind())
    return {
        tuple(sorted(cons['column_names'])): cons['name']
        for cons in inspector.get_unique_constraints(table)
    }


def remove_fk_unique_constraints(table, foreign_keys):
    unique_constraints_map = get_unique_constraints_map(table)
    for fk in foreign_keys:
        constraint_name = unique_constraints_map.get(
            tuple(sorted(fk['constrained_columns'])))
        if constraint_name:
            op.drop_constraint(
                constraint_name=constraint_name,
                table_name=table,
                type_="unique"
            )


def remove_foreign_keys(table, foreign_keys):
    for fk in foreign_keys:
        op.drop_constraint(
            constraint_name=fk['name'],
            table_name=table,
            type_='foreignkey'
        )


def create_foreign_keys(table, foreign_keys):
    for fk in foreign_keys:
        op.create_foreign_key(
            constraint_name=fk['name'],
            source_table=table,
            referent_table=fk['referred_table'],
            local_cols=fk['constrained_columns'],
            remote_cols=fk['referred_columns'],
            ondelete=fk['options'].get('ondelete')
        )


@contextlib.contextmanager
def remove_fks_from_table(table, remove_unique_constraints=False):
    try:
        inspector = sa.inspect(op.get_bind())
        foreign_keys = inspector.get_foreign_keys(table)
        remove_foreign_keys(table, foreign_keys)
        if remove_unique_constraints:
            remove_fk_unique_constraints(table, foreign_keys)
        yield
    finally:
        create_foreign_keys(table, foreign_keys)


def pk_on_alembic_version_table():
    inspector = sa.inspect(op.get_bind())
    pk = inspector.get_pk_constraint('alembic_version')
    if not pk['constrained_columns']:
        op.create_primary_key(op.f('pk_alembic_version'),
                              'alembic_version', ['version_num'])
