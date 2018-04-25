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

from alembic import op
from oslo_utils import uuidutils
import sqlalchemy as sa

from neutron.common import constants as const

"""migrate to pluggable ipam """

# revision identifiers, used by Alembic.
revision = '3b935b28e7a0'
down_revision = 'a8b517cff8ab'


# A simple models for tables with only the fields needed for the migration.
neutron_subnet = sa.Table('subnets', sa.MetaData(),
                          sa.Column('id', sa.String(length=36),
                                    nullable=False))

ipam_subnet = sa.Table('ipamsubnets', sa.MetaData(),
                       sa.Column('id', sa.String(length=36), nullable=False),
                       sa.Column('neutron_subnet_id', sa.String(length=36),
                                 nullable=True))

ip_allocation_pool = sa.Table('ipallocationpools', sa.MetaData(),
                              sa.Column('id', sa.String(length=36),
                                        nullable=False),
                              sa.Column('subnet_id', sa.String(length=36),
                                        sa.ForeignKey('subnets.id',
                                                      ondelete="CASCADE"),
                                        nullable=False),
                              sa.Column('first_ip', sa.String(length=64),
                                        nullable=False),
                              sa.Column('last_ip', sa.String(length=64),
                                        nullable=False))

ipam_allocation_pool = sa.Table('ipamallocationpools', sa.MetaData(),
                                sa.Column('id', sa.String(length=36),
                                          nullable=False),
                                sa.Column('ipam_subnet_id',
                                          sa.String(length=36),
                                          sa.ForeignKey('ipamsubnets.id',
                                                        ondelete="CASCADE"),
                                          nullable=False),
                                sa.Column('first_ip', sa.String(length=64),
                                          nullable=False),
                                sa.Column('last_ip', sa.String(length=64),
                                          nullable=False))

ip_allocation = sa.Table('ipallocations', sa.MetaData(),
                         sa.Column('ip_address', sa.String(length=64),
                                   nullable=False),
                         sa.Column('subnet_id', sa.String(length=36),
                                   sa.ForeignKey('subnets.id',
                                                 ondelete="CASCADE")))

ipam_allocation = sa.Table('ipamallocations', sa.MetaData(),
                           sa.Column('ip_address', sa.String(length=64),
                                     nullable=False, primary_key=True),
                           sa.Column('ipam_subnet_id', sa.String(length=36),
                                     sa.ForeignKey('subnets.id',
                                                   ondelete="CASCADE"),
                                     primary_key=True),
                           sa.Column('status', sa.String(length=36)))


def upgrade():
    """Migrate data to pluggable ipam reference driver.

    Tables 'subnets', 'ipallocationpools' and 'ipallocations' are API exposed
    and always contain up to date data independently from the ipam driver
    in use, so they can be used as a reliable source of data.

    This migration cleans up tables for reference ipam driver and rebuilds them
    from API exposed tables. So this migration will work correctly for both
    types of users:
    - Who used build-in ipam implementation;
    Their ipam data will be migrated to reference ipam driver tables,
    and reference ipam driver becomes default driver.
    - Who switched to reference ipam before Newton;
    Existent reference ipam driver tables are cleaned up and all ipam data is
    regenerated from API exposed tables.
    All existent subnets and ports are still usable after upgrade.
    """
    session = sa.orm.Session(bind=op.get_bind())

    # Make sure destination tables are clean
    session.execute(ipam_subnet.delete())
    session.execute(ipam_allocation_pool.delete())
    session.execute(ipam_allocation.delete())

    map_neutron_id_to_ipam = {}
    subnet_values = []
    for subnet_id, in session.query(neutron_subnet):
        ipam_id = uuidutils.generate_uuid()
        map_neutron_id_to_ipam[subnet_id] = ipam_id
        subnet_values.append(dict(
            id=ipam_id,
            neutron_subnet_id=subnet_id))
    op.bulk_insert(ipam_subnet, subnet_values)

    ipam_pool_values = []
    pools = session.query(ip_allocation_pool)
    for pool in pools:
        new_pool_id = uuidutils.generate_uuid()
        ipam_pool_values.append(dict(
            id=new_pool_id,
            ipam_subnet_id=map_neutron_id_to_ipam[pool.subnet_id],
            first_ip=pool.first_ip,
            last_ip=pool.last_ip))
    op.bulk_insert(ipam_allocation_pool, ipam_pool_values)

    ipam_allocation_values = []
    for ip_alloc in session.query(ip_allocation):
        ipam_allocation_values.append(dict(
            ip_address=ip_alloc.ip_address,
            status=const.IPAM_ALLOCATION_STATUS_ALLOCATED,
            ipam_subnet_id=map_neutron_id_to_ipam[ip_alloc.subnet_id]))
    op.bulk_insert(ipam_allocation, ipam_allocation_values)
    session.commit()
