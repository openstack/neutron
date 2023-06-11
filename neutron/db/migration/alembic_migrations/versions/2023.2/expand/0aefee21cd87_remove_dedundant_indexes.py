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

from alembic import op
import sqlalchemy as sa


"""Remove dedundant indexes

Revision ID: 0aefee21cd87
Revises: 682c319773d7
Create Date: 2023-06-11 04:04:28.536800

"""

# revision identifiers, used by Alembic.
revision = '0aefee21cd87'
down_revision = '682c319773d7'


TABLES_AND_COLUMNS = (
    ('portdataplanestatuses', 'port_id'),
    ('portdnses', 'port_id'),
    ('portuplinkstatuspropagation', 'port_id'),
    ('qos_policies_default', 'project_id'),
    ('quotausages', 'resource'),
    ('quotausages', 'project_id'),
    ('subnet_dns_publish_fixed_ips', 'subnet_id'),
    ('segmenthostmappings', 'segment_id'),
    ('segmenthostmappings', 'host'),
    ('networkdnsdomains', 'network_id'),
    ('floatingipdnses', 'floatingip_id')
)


def upgrade():
    inspector = sa.inspect(op.get_bind())
    for table, column in TABLES_AND_COLUMNS:
        for index in inspector.get_indexes(table):
            if index['column_names'] == [column]:
                op.drop_index(index_name=op.f(index['name']), table_name=table)


def expand_drop_exceptions():
    """Drop the redundant indexes

    This migration will remove the indexes from those columns that are primary
    keys. A primary key creates an index in the table; this second index is
    redundant.
    """
    return {
        sa.Index: list({val[0] for val in TABLES_AND_COLUMNS}),
    }
