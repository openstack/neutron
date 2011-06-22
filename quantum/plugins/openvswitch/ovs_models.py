# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2011 Nicira Networks, Inc.
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
# @author: Somik Behera, Nicira Networks, Inc.
# @author: Brad Hall, Nicira Networks, Inc.
# @author: Dan Wendlandt, Nicira Networks, Inc.


import uuid

from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relation
from quantum.db.models import BASE


class VlanBinding(BASE):
    """Represents a binding of network_id, vlan_id"""
    __tablename__ = 'vlan_bindings'

    vlan_id = Column(Integer, primary_key=True)
    network_id = Column(String(255))

    def __init__(self, vlan_id, network_id):
        self.network_id = network_id
        self.vlan_id = vlan_id

    def __repr__(self):
        return "<VlanBinding(%s,%s)>" % \
          (self.vlan_id, self.network_id)
