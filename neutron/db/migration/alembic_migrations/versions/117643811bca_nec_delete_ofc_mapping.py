# Copyright 2014 NEC Corporation
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

"""nec: delete old ofc mapping tables

Revision ID: 117643811bca
Revises: 81c553f3776c
Create Date: 2014-03-02 05:26:47.073318

"""

# revision identifiers, used by Alembic.
revision = '117643811bca'
down_revision = '81c553f3776c'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.ext import compiler as sa_compiler
from sqlalchemy.sql import expression as sa_expr

from neutron.db import migration


# sqlalchemy does not support the expression:
# INSERT INTO <table> (<column>, ...) (SELECT ...)
# The following class is to support this expression.
# Reference: http://docs.sqlalchemy.org/en/rel_0_9/core/compiler.html
#  section: "Compiling sub-elements of a custom expression construct"

class InsertFromSelect(sa_expr.Executable, sa_expr.ClauseElement):
    _execution_options = (sa_expr.Executable._execution_options.
                          union({'autocommit': True}))

    def __init__(self, insert_spec, select):
        self.insert_spec = insert_spec
        self.select = select


@sa_compiler.compiles(InsertFromSelect)
def visit_insert_from_select(element, compiler, **kw):
    if type(element.insert_spec) == list:
        columns = []
        for column in element.insert_spec:
            columns.append(column.name)
        table = compiler.process(element.insert_spec[0].table, asfrom=True)
        columns = ", ".join(columns)
        sql = ("INSERT INTO %s (%s) (%s)" %
               (table, columns, compiler.process(element.select)))
    else:
        sql = ("INSERT INTO %s (%s)" %
               (compiler.process(element.insert_spec, asfrom=True),
                compiler.process(element.select)))
    return sql


def upgrade():
    # Table definitions below are only used for sqlalchemy to generate
    # SQL statements, so in networks/ports tables only required field
    # are declared. Note that 'quantum_id' in OFC ID mapping tables
    # will be renamed in a later patch (bug 1287432).

    if not migration.schema_has_table('ofctenants'):
        # Assume that, in the database we are migrating from, the
        # configured plugin did not create any ofc tables.
        return

    ofctenants = sa_expr.table(
        'ofctenants',
        sa_expr.column('id'),
        sa_expr.column('quantum_id'))
    ofcnetworks = sa_expr.table(
        'ofcnetworks',
        sa_expr.column('id'),
        sa_expr.column('quantum_id'))
    ofcports = sa_expr.table(
        'ofcports',
        sa_expr.column('id'),
        sa_expr.column('quantum_id'))
    ofcfilters = sa_expr.table(
        'ofcfilters',
        sa_expr.column('id'),
        sa_expr.column('quantum_id'))

    ofctenantmappings = sa_expr.table(
        'ofctenantmappings',
        sa_expr.column('ofc_id'),
        sa_expr.column('quantum_id'))
    ofcnetworkmappings = sa_expr.table(
        'ofcnetworkmappings',
        sa_expr.column('ofc_id'),
        sa_expr.column('quantum_id'))
    ofcportmappings = sa_expr.table(
        'ofcportmappings',
        sa_expr.column('ofc_id'),
        sa_expr.column('quantum_id'))
    ofcfiltermappings = sa_expr.table(
        'ofcfiltermappings',
        sa_expr.column('ofc_id'),
        sa_expr.column('quantum_id'))

    networks = sa_expr.table(
        'networks',
        sa_expr.column('id'),
        sa_expr.column('tenant_id'))
    ports = sa_expr.table(
        'ports',
        sa_expr.column('id'),
        sa_expr.column('network_id'))

    # ofctenants -> ofctenantmappings
    select_obj = sa.select([ofctenants.c.quantum_id,
                            op.inline_literal('/tenants/') + ofctenants.c.id])
    stmt = InsertFromSelect([ofctenantmappings.c.quantum_id,
                             ofctenantmappings.c.ofc_id],
                            select_obj)
    op.execute(stmt)

    # ofcnetworks -> ofcnetworkmappings
    select_obj = ofcnetworks.join(
        networks,
        ofcnetworks.c.quantum_id == networks.c.id)
    select_obj = select_obj.join(
        ofctenantmappings,
        ofctenantmappings.c.quantum_id == networks.c.tenant_id)
    select_obj = sa.select(
        [ofcnetworks.c.quantum_id,
         (ofctenantmappings.c.ofc_id +
          op.inline_literal('/networks/') + ofcnetworks.c.id)],
        from_obj=select_obj)
    stmt = InsertFromSelect([ofcnetworkmappings.c.quantum_id,
                             ofcnetworkmappings.c.ofc_id],
                            select_obj)
    op.execute(stmt)

    # ofcports -> ofcportmappings
    select_obj = ofcports.join(ports, ofcports.c.quantum_id == ports.c.id)
    select_obj = select_obj.join(
        ofcnetworkmappings,
        ofcnetworkmappings.c.quantum_id == ports.c.network_id)
    select_obj = sa.select(
        [ofcports.c.quantum_id,
         (ofcnetworkmappings.c.ofc_id +
          op.inline_literal('/ports/') + ofcports.c.id)],
        from_obj=select_obj)
    stmt = InsertFromSelect([ofcportmappings.c.quantum_id,
                             ofcportmappings.c.ofc_id],
                            select_obj)
    op.execute(stmt)

    # ofcfilters -> ofcfiltermappings
    select_obj = sa.select([ofcfilters.c.quantum_id,
                            op.inline_literal('/filters/') + ofcfilters.c.id])
    stmt = InsertFromSelect([ofcfiltermappings.c.quantum_id,
                             ofcfiltermappings.c.ofc_id],
                            select_obj)
    op.execute(stmt)

    # drop old mapping tables
    op.drop_table('ofctenants')
    op.drop_table('ofcnetworks')
    op.drop_table('ofcports')
    op.drop_table('ofcfilters')
