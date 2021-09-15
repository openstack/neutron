# Copyright (c) 2017 Fujitsu Limited
# All rights reserved
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

from neutron_lib.db import constants as db_const
from neutron_lib.db import model_base
from neutron_lib.db import standard_attr
import sqlalchemy as sa


class Log(standard_attr.HasStandardAttributes, model_base.BASEV2,
          model_base.HasId, model_base.HasProject):
    """Represents neutron logging resource database"""

    __tablename__ = 'logs'

    name = sa.Column(sa.String(db_const.NAME_FIELD_SIZE))
    resource_type = sa.Column(sa.String(36), nullable=False)
    resource_id = sa.Column(sa.String(db_const.UUID_FIELD_SIZE),
                            nullable=True, index=True)
    event = sa.Column(sa.String(255), nullable=False)
    target_id = sa.Column(sa.String(db_const.UUID_FIELD_SIZE),
                          nullable=True, index=True)
    enabled = sa.Column(sa.Boolean())
    api_collections = ['logs']
