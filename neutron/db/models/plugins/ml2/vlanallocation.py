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

from neutron_lib.db import model_base
import sqlalchemy as sa


class VlanAllocation(model_base.BASEV2):
    """Represent allocation state of a vlan_id on a physical network.

    If allocated is False, the vlan_id on the physical_network is
    available for allocation to a tenant network. If allocated is
    True, the vlan_id on the physical_network is in use, either as a
    tenant or provider network.

    When an allocation is released, if the vlan_id for the
    physical_network is inside the pool described by
    VlanTypeDriver.network_vlan_ranges, then allocated is set to
    False. If it is outside the pool, the record is deleted.
    """

    __tablename__ = 'ml2_vlan_allocations'
    __table_args__ = (
        sa.Index('ix_ml2_vlan_allocations_physical_network_allocated',
                 'physical_network', 'allocated'),
        model_base.BASEV2.__table_args__,)

    physical_network = sa.Column(sa.String(64), nullable=False,
                                 primary_key=True)
    vlan_id = sa.Column(sa.Integer, nullable=False, primary_key=True,
                        autoincrement=False)
    allocated = sa.Column(sa.Boolean, nullable=False)

    @classmethod
    def get_segmentation_id(cls):
        return cls.vlan_id
