# Copyright 2016 OpenStack Foundation
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

"""device_owner_ha_replicate_int

Revision ID: 7bbb25278f53
Revises: 4ffceebfcdc
Create Date: 2016-03-22 10:00:43.245503

"""

# revision identifiers, used by Alembic.
revision = '7bbb25278f53'
down_revision = '4ffceebfcdc'

from alembic import op
from neutron_lib import constants
import sqlalchemy as sa


ROUTER_ATTR_TABLE = 'router_extra_attributes'
ROUTER_PORTS_TABLE = 'routerports'
PORTS_TABLE = 'ports'


def upgrade():
    update_device_owner_ha_replicated_interface()


def update_device_owner_ha_replicated_interface():
    router_attr_table = sa.Table(ROUTER_ATTR_TABLE,
                                 sa.MetaData(),
                                 sa.Column('router_id', sa.String(36)),
                                 sa.Column('ha', sa.Boolean),)

    routerports = sa.Table(ROUTER_PORTS_TABLE,
                           sa.MetaData(),
                           sa.Column('router_id', sa.String(36)),
                           sa.Column('port_type', sa.String(255)))

    ports = sa.Table(PORTS_TABLE,
                     sa.MetaData(),
                     sa.Column('device_owner', sa.String(255)),
                     sa.Column('device_id', sa.String(255)))

    session = sa.orm.Session(bind=op.get_bind())
    with session.begin(subtransactions=True):
        for router_attr in session.query(
                router_attr_table).filter(router_attr_table.c.ha):
            session.execute(routerports.update().values(
                port_type=constants.DEVICE_OWNER_HA_REPLICATED_INT).where(
                routerports.c.router_id == router_attr.router_id).where(
                routerports.c.port_type == constants.DEVICE_OWNER_ROUTER_INTF))
            session.execute(ports.update().values(
                device_owner=constants.DEVICE_OWNER_HA_REPLICATED_INT).where(
                ports.c.device_id == router_attr.router_id).where(
                ports.c.device_owner == constants.DEVICE_OWNER_ROUTER_INTF))
    session.commit()
