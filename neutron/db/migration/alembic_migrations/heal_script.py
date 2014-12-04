# Copyright 2014 OpenStack Foundation
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

import logging

import alembic
from alembic import autogenerate as autogen
from alembic import context
from alembic import op

import sqlalchemy
from sqlalchemy import schema as sa_schema
import sqlalchemy.sql.expression as expr
from sqlalchemy.sql import text
from sqlalchemy import types

from neutron.db.migration.models import frozen as frozen_models
from neutron.i18n import _LI, _LW

LOG = logging.getLogger(__name__)

METHODS = {}


def heal():
    # This is needed else the heal script will start spewing
    # a lot of pointless warning messages from alembic.
    LOG.setLevel(logging.INFO)
    if context.is_offline_mode():
        return
    models_metadata = frozen_models.get_metadata()
    # Compare metadata from models and metadata from migrations
    # Diff example:
    # [ ( 'add_table',
    #      Table('bat', MetaData(bind=None),
    #            Column('info', String(), table=<bat>), schema=None)),
    # ( 'remove_table',
    #   Table(u'bar', MetaData(bind=None),
    #         Column(u'data', VARCHAR(), table=<bar>), schema=None)),
    # ( 'add_column',
    #    None,
    #   'foo',
    #   Column('data', Integer(), table=<foo>)),
    # ( 'remove_column',
    #   None,
    #  'foo',
    #  Column(u'old_data', VARCHAR(), table=None)),
    # [ ( 'modify_nullable',
    #     None,
    #     'foo',
    #     u'x',
    #     { 'existing_server_default': None,
    #     'existing_type': INTEGER()},
    #     True,
    #     False)]]
    opts = {
        'compare_type': _compare_type,
        'compare_server_default': _compare_server_default,
    }
    mc = alembic.migration.MigrationContext.configure(op.get_bind(), opts=opts)
    set_storage_engine(op.get_bind(), "InnoDB")
    diff = autogen.compare_metadata(mc, models_metadata)
    for el in diff:
        execute_alembic_command(el)


def execute_alembic_command(command):
    # Commands like add_table, remove_table, add_index, add_column, etc is a
    # tuple and can be handle after running special functions from alembic for
    # them.
    if isinstance(command, tuple):
        # Here methods add_table, drop_index, etc is running. Name of method is
        # the first element of the tuple, arguments to this method comes from
        # the next element(s).
        if command[0] in METHODS:
            METHODS[command[0]](*command[1:])
        else:
            LOG.warning(_LW("Ignoring alembic command %s"), command[0])
    else:
        # For all commands that changing type, nullable or other parameters
        # of the column is used alter_column method from alembic.
        parse_modify_command(command)


def parse_modify_command(command):
    # From arguments of command is created op.alter_column() that has the
    # following syntax:
    # alter_column(table_name, column_name, nullable=None,
    #              server_default=False, new_column_name=None, type_=None,
    #              autoincrement=None, existing_type=None,
    #              existing_server_default=False, existing_nullable=None,
    #              existing_autoincrement=None, schema=None, **kw)
    bind = op.get_bind()
    for modified, schema, table, column, existing, old, new in command:
        if modified.endswith('type'):
            modified = 'type_'
        elif modified.endswith('nullable'):
            modified = 'nullable'
            insp = sqlalchemy.engine.reflection.Inspector.from_engine(bind)
            if column in insp.get_primary_keys(table) and new:
                return
        elif modified.endswith('default'):
            modified = 'server_default'
        if isinstance(new, basestring):
            new = text(new)
        kwargs = {modified: new, 'schema': schema}
        default = existing.get('existing_server_default')
        if default and isinstance(default, sa_schema.DefaultClause):
            if isinstance(default.arg, basestring):
                existing['existing_server_default'] = default.arg
            else:
                existing['existing_server_default'] = default.arg.text
        kwargs.update(existing)
        op.alter_column(table, column, **kwargs)


def alembic_command_method(f):
    METHODS[f.__name__] = f
    return f


@alembic_command_method
def add_table(table):
    # Check if table has already exists and needs just to be renamed
    if not rename(table.name):
        table.create(bind=op.get_bind(), checkfirst=True)


@alembic_command_method
def add_index(index):
    bind = op.get_bind()
    insp = sqlalchemy.engine.reflection.Inspector.from_engine(bind)
    if index.name not in [idx['name'] for idx in
                          insp.get_indexes(index.table.name)]:
        op.create_index(index.name, index.table.name, column_names(index))


@alembic_command_method
def remove_table(table):
    # Tables should not be removed
    pass


@alembic_command_method
def remove_index(index):
    bind = op.get_bind()
    insp = sqlalchemy.engine.reflection.Inspector.from_engine(bind)
    index_names = [idx['name'] for idx in insp.get_indexes(index.table.name)]
    fk_names = [i['name'] for i in insp.get_foreign_keys(index.table.name)]
    if index.name in index_names and index.name not in fk_names:
        op.drop_index(index.name, index.table.name)


@alembic_command_method
def remove_column(schema, table_name, column):
    op.drop_column(table_name, column.name, schema=schema)


@alembic_command_method
def add_column(schema, table_name, column):
    op.add_column(table_name, column.copy(), schema=schema)


@alembic_command_method
def add_constraint(constraint):
    op.create_unique_constraint(constraint.name, constraint.table.name,
                                column_names(constraint))


@alembic_command_method
def remove_constraint(constraint):
    op.drop_constraint(constraint.name, constraint.table.name, type_='unique')


@alembic_command_method
def remove_fk(fk):
    op.drop_constraint(fk.name, fk.parent.name, type_='foreignkey')


@alembic_command_method
def add_fk(fk):
    fk_name = fk.name
    # As per Mike Bayer's comment, using _fk_spec method is preferable to
    # direct access to ForeignKeyConstraint attributes
    fk_spec = alembic.ddl.base._fk_spec(fk)
    fk_table = fk_spec[1]
    fk_ref = fk_spec[4]
    fk_local_cols = fk_spec[2]
    fk_remote_cols = fk_spec[5]
    op.create_foreign_key(fk_name, fk_table, fk_ref, fk_local_cols,
                          fk_remote_cols)


def check_if_table_exists(table):
    # This functions checks if table exists or not
    bind = op.get_bind()
    insp = sqlalchemy.engine.reflection.Inspector.from_engine(bind)
    return (table in insp.get_table_names() and
            table not in frozen_models.renamed_tables)


def rename(table):
    # For tables that were renamed checks if the previous table exists
    # if it does the previous one will be renamed.
    # Returns True/False if it is needed to create new table
    if table in frozen_models.renamed_tables:
        if check_if_table_exists(frozen_models.renamed_tables[table]):
            op.rename_table(frozen_models.renamed_tables[table], table)
            LOG.info(_LI("Table %(old_t)r was renamed to %(new_t)r"), {
                'old_t': table, 'new_t': frozen_models.renamed_tables[table]})
            return True
    return False


def column_names(obj):
    return [col.name for col in obj.columns if hasattr(col, 'name')]


def _compare_type(ctxt, insp_col, meta_col, insp_type, meta_type):
    """Return True if types are different, False if not.

    Return None to allow the default implementation to compare these types.

    :param ctxt: alembic MigrationContext instance
    :param insp_col: reflected column
    :param meta_col: column from model
    :param insp_type: reflected column type
    :param meta_type: column type from model

    """

    # some backends (e.g. mysql) don't provide native boolean type
    BOOLEAN_METADATA = (types.BOOLEAN, types.Boolean)
    BOOLEAN_SQL = BOOLEAN_METADATA + (types.INTEGER, types.Integer)

    if isinstance(meta_type, BOOLEAN_METADATA):
        return not isinstance(insp_type, BOOLEAN_SQL)

    return None  # tells alembic to use the default comparison method


def _compare_server_default(ctxt, ins_col, meta_col, insp_def, meta_def,
                            rendered_meta_def):
    """Compare default values between model and db table.

    Return True if the defaults are different, False if not, or None to
    allow the default implementation to compare these defaults.

    :param ctxt: alembic MigrationContext instance
    :param insp_col: reflected column
    :param meta_col: column from model
    :param insp_def: reflected column default value
    :param meta_def: column default value from model
    :param rendered_meta_def: rendered column default value (from model)

    """

    if (ctxt.dialect.name == 'mysql' and
            isinstance(meta_col.type, sqlalchemy.Boolean)):

        if meta_def is None or insp_def is None:
            return meta_def != insp_def

        return not (
            isinstance(meta_def.arg, expr.True_) and insp_def == "'1'" or
            isinstance(meta_def.arg, expr.False_) and insp_def == "'0'"
        )

    return None  # tells alembic to use the default comparison method


def set_storage_engine(bind, engine):
    insp = sqlalchemy.engine.reflection.Inspector.from_engine(bind)
    if bind.dialect.name == 'mysql':
        for table in insp.get_table_names():
            if insp.get_table_options(table)['mysql_engine'] != engine:
                op.execute("ALTER TABLE %s ENGINE=%s" % (table, engine))
