# Copyright (c) 2019 Red Hat, Inc.
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

from neutron_lib.db import model_base
import sqlalchemy as sa
from sqlalchemy import orm

from neutron.db.models import l3
from neutron_lib.db import constants as db_const


class ConntrackHelper(model_base.BASEV2, model_base.HasId):

    __tablename__ = 'conntrack_helpers'

    router_id = sa.Column(sa.String(db_const.UUID_FIELD_SIZE),
                          sa.ForeignKey('routers.id', ondelete="CASCADE"),
                          nullable=False)
    protocol = sa.Column(sa.String(40), nullable=False)
    port = sa.Column(sa.Integer, nullable=False)
    helper = sa.Column(sa.String(64), nullable=False)

    __table_args__ = (
        sa.UniqueConstraint(
            router_id, protocol, port, helper,
            name='uniq_conntrack_helpers0router_id0protocol0port0helper'),
    )

    router = orm.relationship(l3.Router, load_on_pending=True,
                              backref=orm.backref("conntrack_helpers",
                                                  lazy='subquery',
                                                  uselist=True,
                                                  cascade='delete'))
    revises_on_change = ('router', )
