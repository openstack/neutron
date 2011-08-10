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
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relation, object_mapper

BASE = declarative_base()


class L2NetworkBase(object):
    """Base class for L2Network Models."""
    __table_args__ = {'mysql_engine': 'InnoDB'}

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __getitem__(self, key):
        return getattr(self, key)

    def get(self, key, default=None):
        return getattr(self, key, default)

    def __iter__(self):
        self._i = iter(object_mapper(self).columns)
        return self

    def next(self):
        n = self._i.next().name
        return n, getattr(self, n)

    def update(self, values):
        """Make the model object behave like a dict"""
        for k, v in values.iteritems():
            setattr(self, k, v)

    def iteritems(self):
        """Make the model object behave like a dict.
        Includes attributes from joins."""
        local = dict(self)
        joined = dict([(k, v) for k, v in self.__dict__.iteritems()
                      if not k[0] == '_'])
        local.update(joined)
        return local.iteritems()


class Port(BASE, L2NetworkBase):
    """Represents a port on a l2network plugin"""
    __tablename__ = 'ports'

    uuid = Column(String(255), primary_key=True)
    network_id = Column(String(255), ForeignKey("networks.uuid"),
                        nullable=False)
    interface_id = Column(String(255))
    state = Column(String(8))

    def __init__(self, network_id):
        self.uuid = str(uuid.uuid4())
        self.network_id = network_id
        self.state = "DOWN"

    def __repr__(self):
        return "<Port(%s,%s,%s,%s)>" % (self.uuid, self.network_id,
                                     self.state, self.interface_id)


class Network(BASE, L2NetworkBase):
    """Represents a networ on l2network plugin"""
    __tablename__ = 'networks'

    uuid = Column(String(255), primary_key=True)
    tenant_id = Column(String(255), nullable=False)
    name = Column(String(255))
    ports = relation(Port, order_by=Port.uuid, backref="network")

    def __init__(self, tenant_id, name):
        self.uuid = str(uuid.uuid4())
        self.tenant_id = tenant_id
        self.name = name

    def __repr__(self):
        return "<Network(%s,%s,%s)>" % \
          (self.uuid, self.name, self.tenant_id)


class VlanBinding(BASE, L2NetworkBase):
    """Represents a binding of vlan_id to network_id"""
    __tablename__ = 'vlan_bindings'

    vlan_id = Column(Integer, primary_key=True)
    vlan_name = Column(String(255))
    network_id = Column(String(255), ForeignKey("networks.uuid"), \
                        nullable=False)
    network = relation(Network, uselist=False)

    def __init__(self, vlan_id, vlan_name, network_id):
        self.vlan_id = vlan_id
        self.vlan_name = vlan_name
        self.network_id = network_id

    def __repr__(self):
        return "<VlanBinding(%d,%s,%s)>" % \
          (self.vlan_id, self.vlan_name, self.network_id)


class PortProfile(BASE, L2NetworkBase):
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


class PortProfileBinding(BASE, L2NetworkBase):
    """Represents PortProfile binding to tenant and network"""
    __tablename__ = 'portprofile_bindings'

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(255))

    network_id = Column(String(255), ForeignKey("networks.uuid"), \
                        nullable=False)
    portprofile_id = Column(String(255), ForeignKey("portprofiles.uuid"), \
                            nullable=False)
    default = Column(Boolean)
    network = relation(Network, uselist=False)
    portprofile = relation(PortProfile, uselist=False)

    def __init__(self, tenant_id, network_id, portprofile_id, default):
        self.tenant_id = tenant_id
        self.network_id = network_id
        self.portprofile_id = portprofile_id
        self.default = default

    def __repr__(self):
        return "<PortProfile Binding(%s,%s,%s,%s)>" % \
          (self.tenant_id, self.network_id, self.portprofile_id, self.default)
