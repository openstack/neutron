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
from neutron_lib import constants
from neutron_lib.db import constants as db_const
from oslo_utils import uuidutils
import sqlalchemy as sa


"""security group default rules

Revision ID: c33da356b165
Revises: 6f1145bff34c
Create Date: 2023-05-15 12:32:01.915525

"""

# revision identifiers, used by Alembic.
revision = 'c33da356b165'
down_revision = 'b1199a3adbef'

INGRESS_RULE_DESCRIPTION = "Legacy default SG rule for ingress traffic"
EGRESS_RULE_DESCRIPTION = "Legacy default SG rule for egress traffic"

table_name = 'securitygroupdefaultrules'
rule_direction_enum = sa.Enum(constants.INGRESS_DIRECTION,
                              constants.EGRESS_DIRECTION,
                              name='defaultsecuritygrouprules_direction')

default_template_rules = [
    {
        'id': uuidutils.generate_uuid(),
        'direction': constants.EGRESS_DIRECTION,
        'ethertype': constants.IPv4,
        'used_in_default_sg': True,
        'used_in_non_default_sg': True,
        'description': EGRESS_RULE_DESCRIPTION,
    },
    {
        'id': uuidutils.generate_uuid(),
        'direction': constants.EGRESS_DIRECTION,
        'ethertype': constants.IPv6,
        'used_in_default_sg': True,
        'used_in_non_default_sg': True,
        'description': EGRESS_RULE_DESCRIPTION,
    },
    {
        'id': uuidutils.generate_uuid(),
        'direction': constants.INGRESS_DIRECTION,
        'ethertype': constants.IPv4,
        'remote_group_id': 'PARENT',
        'used_in_default_sg': True,
        'used_in_non_default_sg': False,
        'description': INGRESS_RULE_DESCRIPTION,
    },
    {
        'id': uuidutils.generate_uuid(),
        'direction': constants.INGRESS_DIRECTION,
        'ethertype': constants.IPv6,
        'remote_group_id': 'PARENT',
        'used_in_default_sg': True,
        'used_in_non_default_sg': False,
        'description': INGRESS_RULE_DESCRIPTION,
    },
]


standardattr = sa.Table(
    'standardattributes', sa.MetaData(),
    sa.Column('id', sa.BigInteger(), primary_key=True, autoincrement=True),
    sa.Column('resource_type', sa.String(length=255), nullable=False),
    sa.Column('description', sa.String(length=255)))


def upgrade():
    connection = op.get_bind()
    insp = sa.inspect(connection)
    if table_name in insp.get_table_names():
        # it means that this table was already there so we don't need to do
        # anything else
        return

    sg_templates_table = op.create_table(
        table_name,
        sa.Column('id', sa.String(length=db_const.UUID_FIELD_SIZE),
                  primary_key=True),
        sa.Column('standard_attr_id', sa.BigInteger(),
                  sa.ForeignKey('standardattributes.id', ondelete='CASCADE'),
                  nullable=False),
        sa.Column('remote_group_id',
                  sa.String(length=db_const.UUID_FIELD_SIZE)),
        sa.Column('remote_address_group_id',
                  sa.String(length=db_const.UUID_FIELD_SIZE)),
        sa.Column('direction', rule_direction_enum, nullable=False),
        sa.Column('ethertype', sa.String(length=40)),
        sa.Column('protocol', sa.String(length=40)),
        sa.Column('port_range_min', sa.Integer()),
        sa.Column('port_range_max', sa.Integer()),
        sa.Column('remote_ip_prefix', sa.String(length=255)),
        sa.Column('used_in_default_sg', sa.Boolean(), nullable=False,
                  server_default=sa.sql.false()),
        sa.Column('used_in_non_default_sg', sa.Boolean(), nullable=False,
                  server_default=sa.sql.true()),
        sa.UniqueConstraint('standard_attr_id'))

    # To keep backward compatibility with older releases, by default we need
    # to have 4 default rules created for each default SG, and two of them are
    # also used for every non-default SG as well:
    session = sa.orm.Session(bind=connection)
    for template_rule in default_template_rules:
        res = session.execute(
            sa.insert(standardattr).values({
                'description': template_rule.pop('description'),
                'resource_type': table_name})
        )
        template_rule['standard_attr_id'] = res.inserted_primary_key[0]
        session.execute(sa.insert(sg_templates_table).values(template_rule))
