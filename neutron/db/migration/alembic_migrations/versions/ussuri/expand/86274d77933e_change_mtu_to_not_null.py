# Copyright 2019 OpenStack Foundation
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
import sqlalchemy as sa


"""change_mtu_to_not_null

Revision ID: 86274d77933e
Revises: c3e9d13c4367
Create Date: 2019-08-30 15:52:30.015146

"""

# revision identifiers, used by Alembic.
revision = '86274d77933e'
down_revision = 'c3e9d13c4367'


networks = sa.Table(
    'networks', sa.MetaData(),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('mtu', sa.Integer(), nullable=True))


def upgrade_existing_records():
    session = sa.orm.Session(bind=op.get_bind())
    with session.begin(subtransactions=True):
        for row in session.query(networks):
            if row[1] is None:
                session.execute(networks.update().values(
                    mtu=constants.DEFAULT_NETWORK_MTU).where(
                    networks.c.id == row[0]))
    session.commit()


def upgrade():
    upgrade_existing_records()
    op.alter_column('networks', 'mtu', nullable=False,
                    server_default=str(constants.DEFAULT_NETWORK_MTU),
                    existing_type=sa.INTEGER())
