# Copyright 2020 OpenStack Foundation
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

"""ovn_distributed_device_owner

Revision ID: fd6107509ccd
Revises: 5c85685d616d
Create Date: 2020-06-01 11:16:58.312355

"""

# revision identifiers, used by Alembic.
revision = 'fd6107509ccd'
down_revision = 'dfe425060830'

PORTS_TABLE = 'ports'
OVN_METADATA_PREFIX = 'ovnmeta'


def upgrade():
    update_device_owner_ovn_distributed_ports()


def update_device_owner_ovn_distributed_ports():
    ports = sa.Table(PORTS_TABLE,
                     sa.MetaData(),
                     sa.Column('device_owner', sa.String(255)),
                     sa.Column('device_id', sa.String(255)))

    session = sa.orm.Session(bind=op.get_bind())
    session.execute(ports.update().values(
        device_owner=constants.DEVICE_OWNER_DISTRIBUTED).where(
        ports.c.device_owner == constants.DEVICE_OWNER_DHCP).where(
        ports.c.device_id.like(f'{OVN_METADATA_PREFIX}%')))
    session.commit()
