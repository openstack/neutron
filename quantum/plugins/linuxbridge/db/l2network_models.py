# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012, Cisco Systems, Inc.
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
# @author: Rohit Agarwalla, Cisco Systems, Inc.

import uuid

from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy.orm import relation, object_mapper

from quantum.db.models import BASE
from quantum.db.models import QuantumBase
from quantum.db import models


class VlanID(BASE, QuantumBase):
    """Represents a vlan_id usage"""
    __tablename__ = 'vlan_ids'

    vlan_id = Column(Integer, primary_key=True)
    vlan_used = Column(Boolean)

    def __init__(self, vlan_id):
        self.vlan_id = vlan_id
        self.vlan_used = False

    def __repr__(self):
        return "<VlanID(%d,%s)>" % \
          (self.vlan_id, self.vlan_used)


class VlanBinding(BASE, QuantumBase):
    """Represents a binding of vlan_id to network_id"""
    __tablename__ = 'vlan_bindings'

    vlan_id = Column(Integer, primary_key=True)
    network_id = Column(String(255), nullable=False)

    def __init__(self, vlan_id, network_id):
        self.vlan_id = vlan_id
        self.network_id = network_id

    def __repr__(self):
        return "<VlanBinding(%d,%s,%s)>" % \
          (self.vlan_id, self.network_id)
