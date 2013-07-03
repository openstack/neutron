# Copyright (c) 2012 OpenStack Foundation.
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

from neutron.db import model_base


class NetworkState(model_base.BASEV2):
    """Represents state of vlan_id on physical network."""
    __tablename__ = 'network_states'

    physical_network = sa.Column(sa.String(64), nullable=False,
                                 primary_key=True)
    vlan_id = sa.Column(sa.Integer, nullable=False, primary_key=True,
                        autoincrement=False)
    allocated = sa.Column(sa.Boolean, nullable=False)

    def __init__(self, physical_network, vlan_id):
        self.physical_network = physical_network
        self.vlan_id = vlan_id
        self.allocated = False

    def __repr__(self):
        return "<NetworkState(%s,%d,%s)>" % (self.physical_network,
                                             self.vlan_id, self.allocated)


class NetworkBinding(model_base.BASEV2):
    """Represents binding of virtual network to physical network and vlan."""
    __tablename__ = 'network_bindings'

    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True)
    physical_network = sa.Column(sa.String(64))
    vlan_id = sa.Column(sa.Integer, nullable=False)

    def __init__(self, network_id, physical_network, vlan_id):
        self.network_id = network_id
        self.physical_network = physical_network
        self.vlan_id = vlan_id

    def __repr__(self):
        return "<NetworkBinding(%s,%s,%d)>" % (self.network_id,
                                               self.physical_network,
                                               self.vlan_id)
