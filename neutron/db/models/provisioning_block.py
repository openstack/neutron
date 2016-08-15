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

from neutron.db import standard_attr


class ProvisioningBlock(model_base.BASEV2):
    # the standard attr id of the thing we want to block
    standard_attr_id = (
        sa.Column(sa.BigInteger().with_variant(sa.Integer(), 'sqlite'),
                  sa.ForeignKey(standard_attr.StandardAttribute.id,
                                ondelete="CASCADE"),
                  primary_key=True))
    # the entity that wants to block the status change (e.g. L2 Agent)
    entity = sa.Column(sa.String(255), nullable=False, primary_key=True)
