# Copyright (c) 2016 Intel Corporation.
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

from oslo_versionedobjects import fields as obj_fields

from neutron.objects import base
from neutron.objects import common_types
from neutron.services.auto_allocate import models


@base.NeutronObjectRegistry.register
class AutoAllocatedTopology(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models.AutoAllocatedTopology

    primary_keys = ['project_id']

    fields = {
        'project_id': obj_fields.StringField(),
        'network_id': common_types.UUIDField(),
        'router_id': common_types.UUIDField(nullable=True),
    }

    fields_no_update = ['network_id', 'router_id']
