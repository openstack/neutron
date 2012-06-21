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

from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relation

from quantum.plugins.cisco.db.l2network_models import L2NetworkBase
from quantum.plugins.cisco.db import models
from quantum.plugins.cisco.db.models import BASE


class PortBinding(BASE, L2NetworkBase):
    """Represents Port binding to device interface"""
    __tablename__ = 'port_bindings'

    id = Column(Integer, primary_key=True, autoincrement=True)
    port_id = Column(String(255), ForeignKey("ports.uuid"),
                     nullable=False)
    blade_intf_dn = Column(String(255), nullable=False)
    portprofile_name = Column(String(255))
    vlan_name = Column(String(255))
    vlan_id = Column(Integer)
    qos = Column(String(255))
    tenant_id = Column(String(255))
    instance_id = Column(String(255))
    vif_id = Column(String(255))
    ports = relation(models.Port, uselist=False)

    def __init__(self, port_id, blade_intf_dn, portprofile_name,
                 vlan_name, vlan_id, qos):
        self.port_id = port_id
        self.blade_intf_dn = blade_intf_dn
        self.portprofile_name = portprofile_name
        self.vlan_name = vlan_name
        self.vlan_id = vlan_id
        self.qos = qos

    def __repr__(self):
        return "<PortProfile Binding(%s,%s,%s,%s,%s,%s)>" % (
               self.port_id, self.blade_intf_dn, self.portprofile_name,
               self.vlan_name, self.vlan_id, self.qos)
