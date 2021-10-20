# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from neutron_lib.db import constants as db_const
from neutron_lib.db import model_base
import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy import sql

from neutron.db.models import l3 as l3_models


class MeteringLabelRule(model_base.BASEV2, model_base.HasId):
    direction = sa.Column(sa.Enum('ingress', 'egress',
                                  name='meteringlabels_direction'))
    remote_ip_prefix = sa.Column(sa.String(64))
    source_ip_prefix = sa.Column(sa.String(64))
    destination_ip_prefix = sa.Column(sa.String(64))
    metering_label_id = sa.Column(sa.String(36),
                                  sa.ForeignKey("meteringlabels.id",
                                                ondelete="CASCADE"),
                                  nullable=False)
    excluded = sa.Column(sa.Boolean, default=False, server_default=sql.false())


class MeteringLabel(model_base.BASEV2,
                    model_base.HasId,
                    model_base.HasProject):
    name = sa.Column(sa.String(db_const.NAME_FIELD_SIZE))
    description = sa.Column(sa.String(db_const.LONG_DESCRIPTION_FIELD_SIZE))
    rules = orm.relationship(MeteringLabelRule, backref="label",
                             cascade="delete", lazy="subquery")
    routers = orm.relationship(
        l3_models.Router,
        primaryjoin="MeteringLabel.project_id==Router.project_id",
        foreign_keys='MeteringLabel.project_id',
        lazy='subquery',
        uselist=True)
    shared = sa.Column(sa.Boolean, default=False, server_default=sql.false())
