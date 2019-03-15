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

import sqlalchemy as sa
from sqlalchemy import sql

from neutron_lib.db import model_base


class GeneveAllocation(model_base.BASEV2):

    __tablename__ = 'ml2_geneve_allocations'

    geneve_vni = sa.Column(sa.Integer, nullable=False, primary_key=True,
                           autoincrement=False)
    allocated = sa.Column(sa.Boolean, nullable=False, default=False,
                          server_default=sql.false(), index=True)

    @classmethod
    def get_segmentation_id(cls):
        return cls.geneve_vni


class GeneveEndpoints(model_base.BASEV2):
    """Represents tunnel endpoint in RPC mode."""

    __tablename__ = 'ml2_geneve_endpoints'
    __table_args__ = (
        sa.UniqueConstraint('host',
                            name='unique_ml2_geneve_endpoints0host'),
        model_base.BASEV2.__table_args__
    )
    ip_address = sa.Column(sa.String(64), primary_key=True)
    host = sa.Column(sa.String(255), nullable=True)

    def __repr__(self):
        return "<GeneveTunnelEndpoint(%s)>" % self.ip_address
