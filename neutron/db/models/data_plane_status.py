# Copyright (c) 2017 NEC Corporation.  All rights reserved.
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

from neutron.db import models_v2


class PortDataPlaneStatus(model_base.BASEV2):
    __tablename__ = 'portdataplanestatuses'

    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True, index=True)
    data_plane_status = sa.Column(sa.String(16), nullable=True)
    port = orm.relationship(
        models_v2.Port, load_on_pending=True,
        backref=orm.backref("data_plane_status",
                            lazy='joined', uselist=False,
                            cascade='delete'))
    revises_on_change = ('port', )
