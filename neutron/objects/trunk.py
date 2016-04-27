# Copyright (c) 2016 Mirantis, Inc.
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

from neutron.objects import base
from neutron.services.trunk import models


@obj_base.VersionedObjectRegistry.register
class SubPort(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models.SubPort

    primary_keys = ['port_id', 'trunk_id']

    fields = {
        'port_id': obj_fields.UUIDField(),
        'trunk_id': obj_fields.UUIDField(),
        'segmentation_type': obj_fields.StringField(),
        'segmentation_id': obj_fields.IntegerField(),
    }

    fields_no_update = ['segmentation_type', 'segmentation_id']


@obj_base.VersionedObjectRegistry.register
class Trunk(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models.Trunk

    fields = {
        'id': obj_fields.UUIDField(),
        'tenant_id': obj_fields.UUIDField(),
        'port_id': obj_fields.UUIDField(),
        'sub_ports': obj_fields.ListOfObjectsField(SubPort.__name__),
    }

    fields_no_update = ['tenant_id', 'port_id']

    synthetic_fields = ['sub_ports']
