# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011, Cisco Systems, Inc.
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

from sqlalchemy import Column, Integer, String, ForeignKey, Boolean
from sqlalchemy.orm import relation

from quantum.db.models import BASE


class VlanBinding(BASE):
    """Represents a binding of vlan_id to network_id"""
    __tablename__ = 'vlan_bindings'

    vlan_id = Column(Integer, primary_key=True)
    vlan_name = Column(String(255))
    network_id = Column(String(255), nullable=False)
    #foreign key to networks.uuid

    def __init__(self, vlan_id, vlan_name, network_id):
        self.vlan_id = vlan_id
        self.vlan_name = vlan_name
        self.network_id = network_id

    def __repr__(self):
        return "<VlanBinding(%d,%s,%s)>" % \
          (self.vlan_id, self.vlan_name, self.network_id)


class PortProfile(BASE):
    """Represents L2 network plugin level PortProfile for a network"""
    __tablename__ = 'portprofiles'

    uuid = Column(String(255), primary_key=True)
    name = Column(String(255))
    vlan_id = Column(Integer)
    qos = Column(String(255))

    def __init__(self, name, vlan_id, qos=None):
            self.uuid = uuid.uuid4()
            self.name = name
            self.vlan_id = vlan_id
            self.qos = qos

    def __repr__(self):
        return "<PortProfile(%s,%s,%d,%s)>" % \
          (self.uuid, self.name, self.vlan_id, self.qos)


class PortProfileBinding(BASE):
    """Represents PortProfile binding to tenant and network"""
    __tablename__ = 'portprofile_bindings'

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(255))

    network_id = Column(String(255), nullable=False)
    #foreign key to networks.uuid
    portprofile_id = Column(String(255), nullable=False)
    #foreign key to portprofiles.uuid
    default = Column(Boolean)

    def __init__(self, tenant_id, network_id, portprofile_id, default):
        self.tenant_id = tenant_id
        self.network_id = network_id
        self.portprofile_id = portprofile_id
        self.default = default

    def __repr__(self):
        return "<PortProfile Binding(%s,%s,%s,%s)>" % \
          (self.tenant_id, self.network_id, self.portprofile_id, self.default)
