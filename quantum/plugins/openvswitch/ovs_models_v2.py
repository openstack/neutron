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
# @author: Aaron Rosen, Nicira Networks, Inc.
# @author: Bob Kukura, Red Hat, Inc.


from sqlalchemy import Boolean, Column, ForeignKey, Integer, String

from quantum.db.models_v2 import model_base


class VlanID(model_base.BASEV2):
    """Represents a vlan_id usage"""
    __tablename__ = 'vlan_ids'

    vlan_id = Column(Integer, nullable=False, primary_key=True)
    vlan_used = Column(Boolean, nullable=False)

    def __init__(self, vlan_id):
        self.vlan_id = vlan_id
        self.vlan_used = False

    def __repr__(self):
        return "<VlanID(%d,%s)>" % (self.vlan_id, self.vlan_used)


class VlanBinding(model_base.BASEV2):
    """Represents a binding of network_id to vlan_id."""
    __tablename__ = 'vlan_bindings'

    network_id = Column(String(36), ForeignKey('networks.id',
                                               ondelete="CASCADE"),
                        primary_key=True)
    vlan_id = Column(Integer, nullable=False)

    def __init__(self, vlan_id, network_id):
        self.network_id = network_id
        self.vlan_id = vlan_id

    def __repr__(self):
        return "<VlanBinding(%s,%s)>" % (self.vlan_id, self.network_id)


class TunnelIP(model_base.BASEV2):
    """Represents a remote IP in tunnel mode."""
    __tablename__ = 'tunnel_ips'

    ip_address = Column(String(255), primary_key=True)

    def __init__(self, ip_address):
        self.ip_address = ip_address

    def __repr__(self):
        return "<TunnelIP(%s)>" % (self.ip_address)
