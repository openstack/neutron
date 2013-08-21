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
#

import sqlalchemy as sa

from neutron.db import model_base


class Credential(model_base.BASEV2):
    """Represents credentials for a tenant to control Cisco switches."""

    __tablename__ = 'cisco_ml2_credentials'

    credential_id = sa.Column(sa.String(255))
    tenant_id = sa.Column(sa.String(255), primary_key=True)
    credential_name = sa.Column(sa.String(255), primary_key=True)
    user_name = sa.Column(sa.String(255))
    password = sa.Column(sa.String(255))
