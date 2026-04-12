# Copyright (c) 2026 Red Hat, Inc.
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

from neutron_lib.api.definitions import \
    security_groups_default_statefulness as apidef
from neutron_lib.db import constants as db_const
from neutron_lib.db import model_base
import sqlalchemy as sa
from sqlalchemy import sql


class SecurityGroupDefaultStatefulness(model_base.BASEV2,
                                       model_base.HasId):
    __tablename__ = 'security_groups_default_statefulness'

    project_id = sa.Column(
        sa.String(db_const.PROJECT_ID_FIELD_SIZE),
        nullable=True,
        unique=True)
    stateful = sa.Column(
        sa.Boolean,
        default=True,
        server_default=sql.true(),
        nullable=False)
    api_collections = [apidef.COLLECTION_NAME]
    collection_resource_map = {
        apidef.COLLECTION_NAME: apidef.RESOURCE_NAME}
