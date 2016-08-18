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

from neutron.db import segments_db as segment_model
from neutron.objects import base


@obj_base.VersionedObjectRegistry.register
class NetworkSegment(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = segment_model.NetworkSegment

    fields = {
        'id': obj_fields.UUIDField(),
        'network_id': obj_fields.UUIDField(),
        'network_type': obj_fields.StringField(),
        'physical_network': obj_fields.StringField(nullable=True),
        'segmentation_id': obj_fields.IntegerField(nullable=True),
        'is_dynamic': obj_fields.BooleanField(default=False),
        'segment_index': obj_fields.IntegerField(default=0)
    }

    foreign_keys = {'Network': {'network_id': 'id'}}
