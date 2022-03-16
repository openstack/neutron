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
from neutron_lib.api.definitions import fip_pf_port_range as range_apidef
from neutron_lib.db import constants as db_const


class PortForwarding(standard_attr.HasStandardAttributes,
                     model_base.BASEV2, model_base.HasId):

    __table_args__ = (
        sa.UniqueConstraint('floatingip_id', 'protocol',
                            'external_port_start', 'external_port_end',
                            name='uniq_port_forwardings0floatingip_id0'
                                 'protocol0external_ports'),
        sa.UniqueConstraint('protocol', 'internal_neutron_port_id',
                            'internal_ip_address', 'internal_port_start',
                            'internal_port_end',
                            name='uniq_port_forwardings0ptcl0in_prt_id0'
                                 'in_ip_addr0in_prts')
    )

    floatingip_id = sa.Column(sa.String(db_const.UUID_FIELD_SIZE),
                              sa.ForeignKey('floatingips.id',
                                            ondelete="CASCADE"),
                              nullable=False)
    internal_neutron_port_id = sa.Column(
        sa.String(db_const.UUID_FIELD_SIZE),
        sa.ForeignKey('ports.id', ondelete="CASCADE"),
        nullable=False)
    protocol = sa.Column(sa.String(40), nullable=False)
    internal_ip_address = sa.Column(sa.String(64), nullable=False)
    internal_port_start = sa.Column(sa.Integer, nullable=False)
    external_port_start = sa.Column(sa.Integer, nullable=False)
    internal_port_end = sa.Column(sa.Integer, nullable=False)
    external_port_end = sa.Column(sa.Integer, nullable=False)
    port = orm.relationship(
        models_v2.Port, load_on_pending=True,
        foreign_keys=internal_neutron_port_id,
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
    api_collections = [apidef.ALIAS, range_apidef.ALIAS]
