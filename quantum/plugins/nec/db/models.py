# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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
# @author: Ryota MIBU

import sqlalchemy as sa

from quantum.db import model_base
from quantum.db import models_v2


class HasQuantumId(object):
    """Logical ID on Quantum"""
    quantum_id = sa.Column(sa.String(36), nullable=False)


class OFCTenant(model_base.BASEV2, models_v2.HasId, HasQuantumId):
    """Represents a Tenant on OpenFlow Network/Controller."""


class OFCNetwork(model_base.BASEV2, models_v2.HasId, HasQuantumId):
    """Represents a Network on OpenFlow Network/Controller."""


class OFCPort(model_base.BASEV2, models_v2.HasId, HasQuantumId):
    """Represents a Port on OpenFlow Network/Controller."""


class OFCFilter(model_base.BASEV2, models_v2.HasId, HasQuantumId):
    """Represents a Filter on OpenFlow Network/Controller."""


class PortInfo(model_base.BASEV2, models_v2.HasId):
    """Represents a Virtual Interface."""
    datapath_id = sa.Column(sa.String(36), nullable=False)
    port_no = sa.Column(sa.Integer, nullable=False)
    vlan_id = sa.Column(sa.Integer, nullable=False)
    mac = sa.Column(sa.String(32), nullable=False)


class PacketFilter(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a packet filter"""
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           nullable=False)
    priority = sa.Column(sa.Integer, nullable=False)
    action = sa.Column(sa.String(16), nullable=False)
    # condition
    in_port = sa.Column(sa.String(36), nullable=False)
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
