# Copyright 2018 Openstack Foundation
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
from neutron_lib.db import standard_attr
import sqlalchemy as sa
from sqlalchemy import orm

from neutron.db.models import l3
from neutron.db import models_v2
from neutron_lib.api.definitions import fip_pf_description as apidef
from neutron_lib.db import constants as db_const


class PortForwarding(standard_attr.HasStandardAttributes,
                     model_base.BASEV2, model_base.HasId):

    __table_args__ = (
        sa.UniqueConstraint('floatingip_id', 'external_port', 'protocol',
                            name='uniq_port_forwardings0floatingip_id0'
                                 'external_port0protocol'),
        sa.UniqueConstraint('internal_neutron_port_id', 'socket', 'protocol',
                            name='uniq_port_forwardings0'
                                 'internal_neutron_port_id0socket0'
                                 'protocol')
    )

    floatingip_id = sa.Column(sa.String(db_const.UUID_FIELD_SIZE),
                              sa.ForeignKey('floatingips.id',
                                            ondelete="CASCADE"),
                              nullable=False)
    external_port = sa.Column(sa.Integer, nullable=False)
    internal_neutron_port_id = sa.Column(
        sa.String(db_const.UUID_FIELD_SIZE),
        sa.ForeignKey('ports.id', ondelete="CASCADE"),
        nullable=False)
    protocol = sa.Column(sa.String(40), nullable=False)
    socket = sa.Column(sa.String(36), nullable=False)
    port = orm.relationship(
        models_v2.Port, load_on_pending=True,
        backref=orm.backref("port_forwardings",
                            lazy='subquery', uselist=True,
                            cascade='delete')
    )
    floating_ip = orm.relationship(
        l3.FloatingIP, load_on_pending=True,
        backref=orm.backref("port_forwardings",
                            lazy='subquery', uselist=True,
                            cascade='delete')
    )
    revises_on_change = ('floating_ip', 'port',)
    api_collections = [apidef.ALIAS]
