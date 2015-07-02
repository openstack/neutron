# Copyright 2015 Red Hat, Inc.
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

from oslo_versionedobjects import base as obj_base
from oslo_versionedobjects import fields as obj_fields

from neutron.db.qos import models as qos_db_model
from neutron.objects import base


# TODO(QoS): add rule lists to object fields
# TODO(QoS): implement something for binding networks and ports with policies


@obj_base.VersionedObjectRegistry.register
class QosPolicy(base.NeutronObject):

    db_model = qos_db_model.QosPolicy

    fields = {
        'id': obj_fields.UUIDField(),
        'tenant_id': obj_fields.UUIDField(),
        'name': obj_fields.StringField(),
        'description': obj_fields.StringField(),
        'shared': obj_fields.BooleanField()
    }
