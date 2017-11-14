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

from neutron.db.models import tag as tag_model
from neutron.objects import base


@base.NeutronObjectRegistry.register
class Tag(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = tag_model.Tag

    fields = {
        'tag': obj_fields.StringField(),
        'standard_attr_id': obj_fields.IntegerField()
    }

    primary_keys = ['tag', 'standard_attr_id']
