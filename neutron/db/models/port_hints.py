# Copyright 2023 Ericsson Software Technology
#
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

from neutron.db import models_v2


class PortHints(model_base.BASEV2):
    __tablename__ = 'porthints'
    port_id = sa.Column(
        sa.String(db_const.UUID_FIELD_SIZE),
        sa.ForeignKey('ports.id', ondelete='CASCADE'),
        primary_key=True)
    hints = sa.Column('hints', sa.String(length=4095), nullable=False)
    port = sa.orm.relationship(
        models_v2.Port,
        load_on_pending=True,
        backref=sa.orm.backref(
            'hints', uselist=False, cascade='delete', lazy='subquery'))

    revises_on_change = ('port', )
