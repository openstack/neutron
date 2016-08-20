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


class FlatAllocation(model_base.BASEV2):
    """Represent persistent allocation state of a physical network.

    If a record exists for a physical network, then that physical
    network has been allocated as a flat network.
    """

    __tablename__ = 'ml2_flat_allocations'

    physical_network = sa.Column(sa.String(64), nullable=False,
                                 primary_key=True)
