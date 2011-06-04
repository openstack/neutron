import uuid

from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relation

from quantum.db.models import BASE

class NetworkBinding(BASE):
    """Represents a binding of network_id, vif_id"""
    __tablename__ = 'network_bindings'

    id = Column(Integer, primary_key=True, autoincrement=True)
    network_id = Column(String(255))
    vif_id = Column(String(255))

    def __init__(self, network_id, vif_id):
        self.network_id = network_id
        self.vif_id = vif_id

    def __repr__(self):
        return "<NetworkBinding(%s,%s)>" % \
          (self.network_id, self.vif_id)

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
