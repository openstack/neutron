# Copyright 2026 Red Hat, LLC
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

from neutron_lib.db import api as db_api
from neutron_lib.objects import common_types

from neutron.db.models import bgp as bgp_models
from neutron.db import models_v2
from neutron.objects import base


@base.NeutronObjectRegistry.register
class SubnetBGPLeakRoutes(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = bgp_models.SubnetBGPLeakRoutes

    primary_keys = ['subnet_id']

    fields = {
        'subnet_id': common_types.UUIDField(),
    }

    @classmethod
    @db_api.CONTEXT_READER
    def get_leaked_subnet_cidrs(cls, context):
        """Return (subnet_id, cidr) for all leaked subnets."""
        query = context.session.query(
            models_v2.Subnet.id, models_v2.Subnet.cidr
        ).join(
            bgp_models.SubnetBGPLeakRoutes,
            bgp_models.SubnetBGPLeakRoutes.subnet_id == models_v2.Subnet.id)
        return query.all()
