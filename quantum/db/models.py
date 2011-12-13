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
# @author: Salvatore Orlando, Citrix Systems

import uuid

from sqlalchemy import Column, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relation, object_mapper

from quantum.api import api_common as common

BASE = declarative_base()


class QuantumBase(object):
    """Base class for Quantum Models."""

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


class Port(BASE, QuantumBase):
    """Represents a port on a quantum network"""
    __tablename__ = 'ports'

    uuid = Column(String(255), primary_key=True)
    network_id = Column(String(255), ForeignKey("networks.uuid"),
                        nullable=False)
    interface_id = Column(String(255), nullable=True)
    # Port state - Hardcoding string value at the moment
    state = Column(String(8))
    op_status = Column(String(16))

    def __init__(self, network_id,
                 op_status=common.OperationalStatus.UNKNOWN):
        self.uuid = str(uuid.uuid4())
        self.network_id = network_id
        self.interface_id = None
        self.state = "DOWN"
        self.op_status = op_status

    def __repr__(self):
        return "<Port(%s,%s,%s,%s,%s)>" % (self.uuid, self.network_id,
                                           self.state, self.op_status,
                                           self.interface_id)


class Network(BASE, QuantumBase):
    """Represents a quantum network"""
    __tablename__ = 'networks'

    uuid = Column(String(255), primary_key=True)
    tenant_id = Column(String(255), nullable=False)
    name = Column(String(255))
    ports = relation(Port, order_by=Port.uuid, backref="network")
    op_status = Column(String(16))

    def __init__(self, tenant_id, name,
                 op_status=common.OperationalStatus.UNKNOWN):
        self.uuid = str(uuid.uuid4())
        self.tenant_id = tenant_id
        self.name = name
        self.op_status = op_status

    def __repr__(self):
        return "<Network(%s,%s,%s,%s)>" % \
          (self.uuid, self.name, self.op_status, self.tenant_id)
