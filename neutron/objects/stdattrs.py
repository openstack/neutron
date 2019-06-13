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

from neutron_lib.objects.extensions import standardattributes as stdattr_obj
from oslo_versionedobjects import fields as obj_fields

from neutron.db import standard_attr
from neutron.objects import base


# TODO(ihrachys): add unit tests for the object
@base.NeutronObjectRegistry.register
class StandardAttribute(base.NeutronDbObject):

    # Version 1.0: Initial version
    VERSION = '1.0'

    new_facade = True

    db_model = standard_attr.StandardAttribute

    fields = {
        'id': obj_fields.IntegerField(),
        'resource_type': obj_fields.StringField(),
    }
    fields.update(stdattr_obj.STANDARD_ATTRIBUTES)
