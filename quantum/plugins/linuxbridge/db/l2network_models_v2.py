# Copyright (c) 2012 OpenStack, LLC.
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
from sqlalchemy import orm

from quantum.db import model_base


class VlanID(model_base.BASEV2):
    """Represents a vlan_id usage"""
    __tablename__ = 'vlan_ids'

    vlan_id = sa.Column(sa.Integer, nullable=False, primary_key=True)
    vlan_used = sa.Column(sa.Boolean, nullable=False)

    def __init__(self, vlan_id):
        self.vlan_id = vlan_id
        self.vlan_used = False

    def __repr__(self):
        return "<VlanID(%d,%s)>" % (self.vlan_id, self.vlan_used)


class VlanBinding(model_base.BASEV2):
    """Represents a binding of vlan_id to network_id"""
    __tablename__ = 'vlan_bindings'

    network_id = sa.Column(sa.String(36), sa.ForeignKey('networks.id',
                                                        ondelete="CASCADE"),
                           primary_key=True)
    vlan_id = sa.Column(sa.Integer, nullable=False)

    def __init__(self, vlan_id, network_id):
        self.vlan_id = vlan_id
        self.network_id = network_id

    def __repr__(self):
        return "<VlanBinding(%d,%s)>" % (self.vlan_id, self.network_id)
