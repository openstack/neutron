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

from neutron_lib.db import model_base
from oslo_versionedobjects import fields as obj_fields
import sqlalchemy as sa

from neutron.db import standard_attr
from neutron.objects import base as objects_base
from neutron.objects import common_types
from neutron.tests.unit.objects import test_base
from neutron.tests.unit import testlib_api


class FakeDbModelWithStandardAttributes(
        standard_attr.HasStandardAttributes, model_base.BASEV2):
    id = sa.Column(sa.String(36), primary_key=True, nullable=False)
    item = sa.Column(sa.String(64))
    api_collections = []
    collection_resource_map = {}
    tag_support = False


@objects_base.NeutronObjectRegistry.register_if(False)
class FakeObjectWithStandardAttributes(objects_base.NeutronDbObject):
    VERSION = '1.0'
    db_model = FakeDbModelWithStandardAttributes
    fields = {
        'id': common_types.UUIDField(),
        'item': obj_fields.StringField(),
    }


class HasStandardAttributesDbTestCase(test_base.BaseDbObjectTestCase,
                                      testlib_api.SqlTestCase):
    _test_class = FakeObjectWithStandardAttributes


class HasStandardAttributesTestCase(test_base.BaseObjectIfaceTestCase):
    _test_class = FakeObjectWithStandardAttributes
