# Copyright 2020 Red Hat, Inc.
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

from neutron_lib import constants as n_const
from neutron_lib.db import constants as db_const
from neutron_lib.db import model_base
import sqlalchemy as sa

from neutron.db import models_v2


class PortNumaAffinityPolicy(model_base.BASEV2):
    __tablename__ = 'portnumaaffinitypolicies'
    port_id = sa.Column(sa.String(db_const.UUID_FIELD_SIZE),
                        sa.ForeignKey('ports.id', ondelete='CASCADE'),
                        primary_key=True)
    numa_affinity_policy = sa.Column(sa.Enum(*n_const.PORT_NUMA_POLICIES,
                                             name='numa_affinity_policy'))
    port = sa.orm.relationship(
        models_v2.Port, load_on_pending=True,
        backref=sa.orm.backref('numa_affinity_policy', uselist=False,
                               cascade='delete', lazy='joined'))

    revises_on_change = ('port', )
