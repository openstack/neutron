# Copyright (c) 2017 Fujitsu Limited
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

from neutron_lib.objects import common_types
from neutron_lib.objects.logapi import event_types
from neutron_lib.services.logapi import constants as log_const
from oslo_versionedobjects import fields as obj_fields

from neutron.db.models import loggingapi as log_db
from neutron.objects import base


@base.NeutronObjectRegistry.register
class Log(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = log_db.Log

    fields = {
        'id': common_types.UUIDField(),
        'project_id': obj_fields.StringField(nullable=True),
        'name': obj_fields.StringField(nullable=True),
        'resource_type': obj_fields.StringField(),
        'resource_id': common_types.UUIDField(nullable=True, default=None),
        'target_id': common_types.UUIDField(nullable=True, default=None),
        'event': event_types.SecurityEventField(default=log_const.ALL_EVENT),
        'enabled': obj_fields.BooleanField(default=True),
    }

    fields_no_update = ['project_id', 'resource_type', 'resource_id',
                        'target_id', 'event']
