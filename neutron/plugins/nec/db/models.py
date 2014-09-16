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

from neutron.db import model_base
from neutron.db import models_v2


"""New mapping tables."""


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
