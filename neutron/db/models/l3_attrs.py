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

from neutron_lib.db import model_base
import sqlalchemy as sa
from sqlalchemy import orm


class RouterExtraAttributes(model_base.BASEV2):
    """Additional attributes for a Virtual Router."""

    # NOTE(armando-migliaccio): this model can be a good place to
    # add extension attributes to a Router model. Each case needs
    # to be individually examined, however 'distributed' and other
    # simple ones fit the pattern well.
    __tablename__ = "router_extra_attributes"
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id', ondelete="CASCADE"),
                          primary_key=True)
    # Whether the router is a legacy (centralized) or a distributed one
    distributed = sa.Column(sa.Boolean, default=False,
                            server_default=sa.sql.false(),
                            nullable=False)
    # Whether the router is to be considered a 'service' router
    service_router = sa.Column(sa.Boolean, default=False,
                               server_default=sa.sql.false(),
                               nullable=False)
    ha = sa.Column(sa.Boolean, default=False,
                   server_default=sa.sql.false(),
                   nullable=False)
    ha_vr_id = sa.Column(sa.Integer())
    # Availability Zone support
    availability_zone_hints = sa.Column(sa.String(255))
    enable_default_route_ecmp = sa.Column(sa.Boolean, default=False,
                                          server_default=sa.sql.false(),
                                          nullable=False)
    enable_default_route_bfd = sa.Column(sa.Boolean, default=False,
                                         server_default=sa.sql.false(),
                                         nullable=False)

    router = orm.relationship(
        'Router', load_on_pending=True,
        backref=orm.backref("extra_attributes", lazy='joined',
                            uselist=False, cascade='delete'))
    revises_on_change = ('router', )
