# Copyright 2013 OpenStack Foundation.
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

from neutron_lib.db import constants as db_const
from neutron_lib.db import model_base
import sqlalchemy as sa


class ProviderResourceAssociation(model_base.BASEV2):
    provider_name = sa.Column(sa.String(db_const.NAME_FIELD_SIZE),
                              nullable=False, primary_key=True)
    # should be manually deleted on resource deletion
    resource_id = sa.Column(sa.String(36), nullable=False, primary_key=True,
                            unique=True)
