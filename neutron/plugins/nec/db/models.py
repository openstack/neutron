# Copyright 2012 NEC Corporation.  All rights reserved.
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

import sqlalchemy as sa
from sqlalchemy import orm

from neutron.db import l3_db
from neutron.db import model_base
from neutron.db import models_v2


# New mapping tables.


class OFCId(object):
    """Resource ID on OpenFlow Controller."""
    ofc_id = sa.Column(sa.String(255), unique=True, nullable=False)


class NeutronId(object):
    """Logical ID on Neutron."""
    neutron_id = sa.Column(sa.String(36), primary_key=True)


class OFCTenantMapping(model_base.BASEV2, NeutronId, OFCId):
    """Represents a Tenant on OpenFlow Network/Controller."""


class OFCNetworkMapping(model_base.BASEV2, NeutronId, OFCId):
    """Represents a Network on OpenFlow Network/Controller."""


class OFCPortMapping(model_base.BASEV2, NeutronId, OFCId):
    """Represents a Port on OpenFlow Network/Controller."""


class OFCRouterMapping(model_base.BASEV2, NeutronId, OFCId):
    """Represents a router on OpenFlow Network/Controller."""


class OFCFilterMapping(model_base.BASEV2, NeutronId, OFCId):
    """Represents a Filter on OpenFlow Network/Controller."""


class PortInfo(model_base.BASEV2):
    """Represents a Virtual Interface."""
    id = sa.Column(sa.String(36),
                   sa.ForeignKey('ports.id', ondelete="CASCADE"),
                   primary_key=True)
    datapath_id = sa.Column(sa.String(36), nullable=False)
    port_no = sa.Column(sa.Integer, nullable=False)
    vlan_id = sa.Column(sa.Integer, nullable=False)
    mac = sa.Column(sa.String(32), nullable=False)
    port = orm.relationship(
        models_v2.Port,
        backref=orm.backref("portinfo",
                            lazy='joined', uselist=False,
                            cascade='delete'))


class RouterProvider(models_v2.model_base.BASEV2):
    """Represents a binding of router_id to provider."""
    provider = sa.Column(sa.String(255))
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id', ondelete="CASCADE"),
                          primary_key=True)

    router = orm.relationship(l3_db.Router, uselist=False,
                              backref=orm.backref('provider', uselist=False,
                                                  lazy='joined',
                                                  cascade='delete'))


class PacketFilter(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a packet filter."""
    name = sa.Column(sa.String(255))
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           nullable=False)
    priority = sa.Column(sa.Integer, nullable=False)
    action = sa.Column(sa.String(16), nullable=False)
    # condition
    in_port = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        nullable=True)
    src_mac = sa.Column(sa.String(32), nullable=False)
    dst_mac = sa.Column(sa.String(32), nullable=False)
    eth_type = sa.Column(sa.Integer, nullable=False)
    src_cidr = sa.Column(sa.String(64), nullable=False)
    dst_cidr = sa.Column(sa.String(64), nullable=False)
    protocol = sa.Column(sa.String(16), nullable=False)
    src_port = sa.Column(sa.Integer, nullable=False)
    dst_port = sa.Column(sa.Integer, nullable=False)
    # status
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)
    status = sa.Column(sa.String(16), nullable=False)

    network = orm.relationship(
        models_v2.Network,
        backref=orm.backref('packetfilters', lazy='joined', cascade='delete'),
        uselist=False)
    in_port_ref = orm.relationship(
        models_v2.Port,
        backref=orm.backref('packetfilters', lazy='joined', cascade='delete'),
        primaryjoin="Port.id==PacketFilter.in_port",
        uselist=False)
