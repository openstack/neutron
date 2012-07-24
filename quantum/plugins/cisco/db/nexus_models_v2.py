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

from sqlalchemy import Column, Integer, String

from quantum.db import model_base
from quantum.plugins.cisco.db.l2network_models import L2NetworkBase


class NexusPortBinding(model_base.BASEV2, L2NetworkBase):
    """Represents a binding of nexus port to vlan_id"""
    __tablename__ = 'nexusport_bindings'

    id = Column(Integer, primary_key=True, autoincrement=True)
    port_id = Column(String(255))
    vlan_id = Column(Integer, nullable=False)

    def __init__(self, port_id, vlan_id):
        self.port_id = port_id
        self.vlan_id = vlan_id

    def __repr__(self):
        return "<NexusPortBinding (%s,%d)>" % (self.port_id, self.vlan_id)
