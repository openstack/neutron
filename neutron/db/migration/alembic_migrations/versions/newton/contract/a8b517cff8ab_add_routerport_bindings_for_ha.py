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

from alembic import op
from neutron_lib import constants
import sqlalchemy as sa


"""Add routerport bindings for L3 HA

Revision ID: a8b517cff8ab
Revises: a8b517cff8ab
Create Date: 2016-07-18 14:31:45.725516

"""

# revision identifiers, used by Alembic.
revision = 'a8b517cff8ab'
down_revision = '7d9d8eeec6ad'


HA_AGENT_BINDINGS = 'ha_router_agent_port_bindings'
ROUTER_PORTS = 'routerports'


def upgrade():
    ha_bindings = sa.Table(
        HA_AGENT_BINDINGS,
        sa.MetaData(),
        sa.Column('port_id', sa.String(36)),
        sa.Column('router_id', sa.String(36)),
        sa.Column('l3_agent_id', sa.String(36)),
        sa.Column('state', sa.Enum(constants.HA_ROUTER_STATE_ACTIVE,
                                   constants.HA_ROUTER_STATE_STANDBY,
                                   name='l3_ha_states'))
    )
    router_ports = sa.Table(ROUTER_PORTS,
                            sa.MetaData(),
                            sa.Column('router_id', sa.String(36)),
                            sa.Column('port_id', sa.String(36)),
                            sa.Column('port_type', sa.String(255)))
    session = sa.orm.Session(bind=op.get_bind())
    with session.begin(subtransactions=True):
        router_port_tuples = set()
        for ha_bind in session.query(ha_bindings):
            router_port_tuples.add((ha_bind.router_id, ha_bind.port_id))
        # we have to remove any from the bulk insert that may already exist
        # as a result of Ifd3e007aaf2a2ed8123275aa3a9f540838e3c003 being
        # back-ported
        for router_port in session.query(router_ports).filter(
                router_ports.c.port_type ==
                constants.DEVICE_OWNER_ROUTER_HA_INTF):
            router_port_tuples.discard((router_port.router_id,
                                        router_port.port_id))
        new_records = [dict(router_id=router_id, port_id=port_id,
                            port_type=constants.DEVICE_OWNER_ROUTER_HA_INTF)
                       for router_id, port_id in router_port_tuples]
    op.bulk_insert(router_ports, new_records)
    session.commit()
