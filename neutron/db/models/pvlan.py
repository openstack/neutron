# Copyright (c) 2026 Red Hat Inc.
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

from neutron_lib.db import model_base
from neutron_lib.services.pvlan import constants as pvlan_const
import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy import sql

from neutron.db import models_v2


class NetworkPVLAN(model_base.BASEV2):

    __tablename__ = 'networkpvlan'

    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True)

    pvlan = sa.Column(sa.Boolean(), nullable=False, default=False,
                      server_default=sql.false())

    # Add a relationship to the Network model in order to instruct
    # SQLAlchemy to eagerly load this association
    network = orm.relationship(models_v2.Network,
                               load_on_pending=True,
                               backref=orm.backref("pvlan",
                                                   lazy='joined',
                                                   uselist=False,
                                                   cascade='delete'))
    revises_on_change = ('network', )


class PortPVLAN(model_base.BASEV2):

    __tablename__ = 'portpvlan'

    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)

    pvlan_type = sa.Column(sa.Enum(*pvlan_const.PVLAN_TYPES,
                           name='pvlan_type_enum'),
                           nullable=False)
    pvlan_community = sa.Column(sa.String(255), nullable=True)

    # Add a relationship to the Port model in order to instruct
    # SQLAlchemy to eagerly load this association
    port = orm.relationship(models_v2.Port,
                            load_on_pending=True,
                            backref=orm.backref("pvlan",
                                                lazy='joined',
                                                uselist=False,
                                                cascade='delete'))
    revises_on_change = ('port', )
