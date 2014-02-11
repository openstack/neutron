# Copyright (c) 2013 OpenStack Foundation
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


import sqlalchemy as sa

from neutron.db import model_base


class NexusPortBinding(model_base.BASEV2):
    """Represents a binding of VM's to nexus ports."""

    __tablename__ = "cisco_ml2_nexusport_bindings"

    binding_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    port_id = sa.Column(sa.String(255))
    vlan_id = sa.Column(sa.Integer, nullable=False)
    switch_ip = sa.Column(sa.String(255))
    instance_id = sa.Column(sa.String(255))

    def __repr__(self):
        """Just the binding, without the id key."""
        return ("<NexusPortBinding(%s,%s,%s,%s)>" %
                (self.port_id, self.vlan_id, self.switch_ip, self.instance_id))

    def __eq__(self, other):
        """Compare only the binding, without the id key."""
        return (
            self.port_id == other.port_id and
            self.vlan_id == other.vlan_id and
            self.switch_ip == other.switch_ip and
            self.instance_id == other.instance_id
        )
