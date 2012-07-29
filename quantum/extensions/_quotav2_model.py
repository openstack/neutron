# Copyright (c) 2012 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sqlalchemy as sa

from quantum.db import model_base
from quantum.db import models_v2


class Quota(model_base.BASEV2, models_v2.HasId):
    """Represent a single quota override for a tenant.

    If there is no row for a given tenant id and resource, then the
    default for the quota class is used.
    """
    tenant_id = sa.Column(sa.String(255), index=True)
    resource = sa.Column(sa.String(255))
    limit = sa.Column(sa.Integer)
