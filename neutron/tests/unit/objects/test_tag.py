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

from neutron.objects import tag
from neutron.tests.unit.objects import test_base as obj_test_base
from neutron.tests.unit import testlib_api


class TagIfaceObjectTestCase(obj_test_base.BaseObjectIfaceTestCase):

    _test_class = tag.Tag


class TagDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                          testlib_api.SqlTestCase):

    _test_class = tag.Tag

    def setUp(self):
        super().setUp()
        self.update_obj_fields(
            {
                'standard_attr_id':
                    lambda: self._create_test_standard_attribute_id()
            })

    def test_case_sensitive_tags(self):
        # All objects will have the same standard_attr_id value
        obj1 = self._make_object({'standard_attr_id': 1, 'tag': 'tag1'})
        obj2 = self._make_object({'standard_attr_id': 1, 'tag': 'Tag1'})
        obj3 = self._make_object({'standard_attr_id': 1, 'tag': 'TAG1'})
        obj1.create()
        obj2.create()
        obj3.create()
