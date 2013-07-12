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

from neutron.db import model_base


class NexusPortBinding(model_base.BASEV2):
    """Represents a binding of VM's to nexus ports."""

    __tablename__ = "nexusport_bindings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    port_id = Column(String(255))
    vlan_id = Column(Integer, nullable=False)
    switch_ip = Column(String(255))
    instance_id = Column(String(255))

    def __init__(self, port_id, vlan_id, switch_ip, instance_id):
        self.port_id = port_id
        self.vlan_id = vlan_id
        self.switch_ip = switch_ip
        self.instance_id = instance_id

    def __repr__(self):
        return "<NexusPortBinding (%s,%d, %s, %s)>" % \
            (self.port_id, self.vlan_id, self.switch_ip, self.instance_id)

    def __eq__(self, other):
        return (
            self.port_id == other.port_id and
            self.vlan_id == other.vlan_id and
            self.switch_ip == other.switch_ip and
            self.instance_id == other.instance_id
        )
