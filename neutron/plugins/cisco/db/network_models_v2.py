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
#
# @author: Rohit Agarwalla, Cisco Systems, Inc.

from sqlalchemy import Column, Integer, String, Boolean

from neutron.db import model_base
from neutron.openstack.common import uuidutils


class VlanID(model_base.BASEV2):
    """Represents a vlan_id usage."""
    __tablename__ = 'cisco_vlan_ids'

    vlan_id = Column(Integer, primary_key=True)
    vlan_used = Column(Boolean)

    def __init__(self, vlan_id):
        self.vlan_id = vlan_id
        self.vlan_used = False

    def __repr__(self):
        return "<VlanID(%d,%s)>" % (self.vlan_id, self.vlan_used)


class QoS(model_base.BASEV2):
    """Represents QoS for a tenant."""

    __tablename__ = 'qoss'

    qos_id = Column(String(255))
    tenant_id = Column(String(255), primary_key=True)
    qos_name = Column(String(255), primary_key=True)
    qos_desc = Column(String(255))

    def __init__(self, tenant_id, qos_name, qos_desc):
        self.qos_id = uuidutils.generate_uuid()
        self.tenant_id = tenant_id
        self.qos_name = qos_name
        self.qos_desc = qos_desc

    def __repr__(self):
        return "<QoS(%s,%s,%s,%s)>" % (self.qos_id, self.tenant_id,
                                       self.qos_name, self.qos_desc)


class Credential(model_base.BASEV2):
    """Represents credentials for a tenant."""

    __tablename__ = 'credentials'

    credential_id = Column(String(255))
    tenant_id = Column(String(255), primary_key=True)
    credential_name = Column(String(255), primary_key=True)
    user_name = Column(String(255))
    password = Column(String(255))

    def __init__(self, tenant_id, credential_name, user_name, password):
        self.credential_id = uuidutils.generate_uuid()
        self.tenant_id = tenant_id
        self.credential_name = credential_name
        self.user_name = user_name
        self.password = password

    def __repr__(self):
        return "<Credentials(%s,%s,%s,%s,%s)>" % (self.credential_id,
                                                  self.tenant_id,
                                                  self.credential_name,
                                                  self.user_name,
                                                  self.password)
