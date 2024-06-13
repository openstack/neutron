# Copyright 2016 Hewlett Packard Enterprise Development Company, LP
# All Rights Reserved.
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

from neutron_lib.db import constants as db_const
from neutron_lib.db import model_base
import sqlalchemy as sa
from sqlalchemy import orm

from neutron.db import models_v2


class SubnetServiceType(model_base.BASEV2):
    """Subnet Service Types table"""

    __tablename__ = "subnet_service_types"

    subnet_id = sa.Column(sa.String(36),
                          sa.ForeignKey('subnets.id', ondelete="CASCADE"))
    # Service types must be valid device owners, therefore share max length
    service_type = sa.Column(sa.String(
        length=db_const.DEVICE_OWNER_FIELD_SIZE))
    subnet = orm.relationship(models_v2.Subnet, load_on_pending=True,
                              backref=orm.backref('service_types',
                                                  lazy='selectin',
                                                  cascade='all, delete-orphan',
                                                  uselist=True))
    __table_args__ = (
        sa.PrimaryKeyConstraint('subnet_id', 'service_type'),
        model_base.BASEV2.__table_args__
    )
    revises_on_change = ('subnet', )
