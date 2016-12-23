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

from neutron_lib.db import constants as db_const
from neutron_lib.db import model_base
import sqlalchemy as sa


class AddressScope(model_base.BASEV2, model_base.HasId, model_base.HasProject):
    """Represents a neutron address scope."""

    __tablename__ = "address_scopes"

    name = sa.Column(sa.String(db_const.NAME_FIELD_SIZE), nullable=False)
    shared = sa.Column(sa.Boolean, nullable=False)
    ip_version = sa.Column(sa.Integer(), nullable=False)
