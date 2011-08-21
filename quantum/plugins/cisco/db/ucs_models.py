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

from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relation

from quantum.plugins.cisco.db.l2network_models import L2NetworkBase
from quantum.plugins.cisco.db import models
from quantum.plugins.cisco.db.models import BASE


class UcsmBinding(BASE, L2NetworkBase):
    """Represents a binding of ucsm to network_id"""
    __tablename__ = 'ucsm_bindings'

    id = Column(Integer, primary_key=True, autoincrement=True)
    ucsm_ip = Column(String(255))
    network_id = Column(String(255), ForeignKey("networks.uuid"),
                        nullable=False)
    network = relation(models.Network)

    def __init__(self, ucsm_ip, network_id):
        self.ucsm_ip = ucsm_ip
        self.network_id = network_id

    def __repr__(self):
        return "<UcsmBinding(%s,%s)>" % \
          (self.ucsm_ip, self.network_id)


class DynamicVnic(BASE, L2NetworkBase):
    """Represents Cisco UCS Dynamic Vnics"""
    __tablename__ = 'dynamic_vnics'

    uuid = Column(String(255), primary_key=True)
    device_name = Column(String(255))
    blade_id = Column(String(255), ForeignKey("ucs_blades.uuid"),
                                                    nullable=False)
    vnic_state = Column(String(255))
    blade_intf_dn = Column(String(255))
    blade_intf_order = Column(String(255))
    blade_int_link_state = Column(String(255))
    blade_intf_oper_state = Column(String(255))
    blade_intf_inst_type = Column(String(255))
    blade_intf_reservation = Column(String(255))

    def __init__(self, device_name, blade_id, vnic_state):
        self.uuid = uuid.uuid4()
        self.device_name = device_name
        self.blade_id = blade_id
        self.vnic_state = vnic_state

    def __repr__(self):
        return "<Dyanmic Vnic(%s,%s,%s,%s)>" % \
          (self.uuid, self.device_name, self.blade_id,
           self.vnic_state)


class UcsBlade(BASE, L2NetworkBase):
    """Represents details of ucs blades"""
    __tablename__ = 'ucs_blades'

    uuid = Column(String(255), primary_key=True)
    mgmt_ip = Column(String(255))
    mac_addr = Column(String(255))
    chassis_id = Column(String(255))
    ucsm_ip = Column(String(255))
    blade_state = Column(String(255))
    vnics_used = Column(Integer)
    hostname = Column(String(255))
    dynamic_vnics = relation(DynamicVnic, order_by=DynamicVnic.uuid,
                                                      backref="blade")

    def __init__(self, mgmt_ip, mac_addr, chassis_id, ucsm_ip,
                 blade_state, vnics_used, hostname):
        self.uuid = uuid.uuid4()
        self.mgmt_ip = mgmt_ip
        self.mac_addr = mac_addr
        self.chassis_id = chassis_id
        self.ucsm_ip = ucsm_ip
        self.blade_state = blade_state
        self.vnics_used = vnics_used
        self.hostname = hostname

    def __repr__(self):
        return "<UcsBlades (%s,%s,%s,%s,%s,%s,%s,%s)>" % \
       (self.uuid, self.mgmt_ip, self.mac_addr, self.chassis_id,
        self.ucsm_ip, self.blade_state, self.vnics_used, self.hostname)


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
        return "<PortProfile Binding(%s,%s,%s,%s,%s,%s)>" % \
          (self.port_id, self.blade_intf_dn, self.portprofile_name,
                                self.vlan_name, self.vlan_id, self.qos)
