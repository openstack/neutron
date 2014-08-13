# Copyright 2013 Mellanox Technologies, Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sqlalchemy as sa
from sqlalchemy import sql

from neutron.db import model_base


class SegmentationIdAllocation(model_base.BASEV2):
    """Represents allocation state of segmentation_id on physical network."""
    __tablename__ = 'segmentation_id_allocation'

    physical_network = sa.Column(sa.String(64), nullable=False,
                                 primary_key=True)
    segmentation_id = sa.Column(sa.Integer, nullable=False, primary_key=True,
                                autoincrement=False)
    allocated = sa.Column(sa.Boolean, nullable=False, default=False,
                          server_default=sql.false())

    def __init__(self, physical_network, segmentation_id):
        self.physical_network = physical_network
        self.segmentation_id = segmentation_id
        self.allocated = False

    def __repr__(self):
        return "<SegmentationIdAllocation(%s,%d,%s)>" % (self.physical_network,
                                                         self.segmentation_id,
                                                         self.allocated)


class NetworkBinding(model_base.BASEV2):
    """Represents binding of virtual network.

    Binds network to physical_network and segmentation_id
    """
    __tablename__ = 'mlnx_network_bindings'

    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True)
    network_type = sa.Column(sa.String(32), nullable=False)
    physical_network = sa.Column(sa.String(64))
    segmentation_id = sa.Column(sa.Integer, nullable=False)

    def __init__(self, network_id, network_type, physical_network, vlan_id):
        self.network_id = network_id
        self.network_type = network_type
        self.physical_network = physical_network
        self.segmentation_id = vlan_id

    def __repr__(self):
        return "<NetworkBinding(%s,%s,%s,%d)>" % (self.network_id,
                                                  self.network_type,
                                                  self.physical_network,
                                                  self.segmentation_id)


class PortProfileBinding(model_base.BASEV2):
    """Represents port profile binding to the port on virtual network."""
    __tablename__ = 'port_profile'

    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    vnic_type = sa.Column(sa.String(32), nullable=False)

    def __init__(self, port_id, vnic_type):
        self.port_id = port_id
        self.vnic_type = vnic_type

    def __repr__(self):
        return "<PortProfileBinding(%s,%s)>" % (self.port_id,
                                                self.vnic_type)
