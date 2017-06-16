#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import gc

from neutron_lib import context
from sqlalchemy.ext import declarative
import testtools

from neutron.db import standard_attr
from neutron.tests import base
from neutron.tests.unit import testlib_api


class StandardAttrTestCase(base.BaseTestCase):
    def setUp(self):
        super(StandardAttrTestCase, self).setUp()
        self.addCleanup(gc.collect)

    def _make_decl_base(self):
        # construct a new base so we don't interfere with the main
        # base used in the sql test fixtures
        return declarative.declarative_base(
            cls=standard_attr.model_base.NeutronBaseV2)

    def test_standard_attr_resource_model_map(self):
        rs_map = standard_attr.get_standard_attr_resource_model_map()
        base = self._make_decl_base()

        class MyModel(standard_attr.HasStandardAttributes,
                      standard_attr.model_base.HasId,
                      base):
            api_collections = ['my_resource', 'my_resource2']

        rs_map = standard_attr.get_standard_attr_resource_model_map()
        self.assertEqual(MyModel, rs_map['my_resource'])
        self.assertEqual(MyModel, rs_map['my_resource2'])

        class Dup(standard_attr.HasStandardAttributes,
                  standard_attr.model_base.HasId,
                  base):
            api_collections = ['my_resource']

        with testtools.ExpectedException(RuntimeError):
            standard_attr.get_standard_attr_resource_model_map()

    def test_standard_attr_resource_parent_map(self):
        base = self._make_decl_base()

        class TagSupportModel(standard_attr.HasStandardAttributes,
                              standard_attr.model_base.HasId,
                              base):
            collection_resource_map = {'collection_name': 'member_name'}
            tag_support = True

        class TagUnsupportModel(standard_attr.HasStandardAttributes,
                                standard_attr.model_base.HasId,
                                base):
            collection_resource_map = {'collection_name2': 'member_name2'}
            tag_support = False

        class TagUnsupportModel2(standard_attr.HasStandardAttributes,
                                 standard_attr.model_base.HasId,
                                 base):
            collection_resource_map = {'collection_name3': 'member_name3'}

        parent_map = standard_attr.get_tag_resource_parent_map()
        self.assertEqual('member_name', parent_map['collection_name'])
        self.assertNotIn('collection_name2', parent_map)
        self.assertNotIn('collection_name3', parent_map)

        class DupTagSupportModel(standard_attr.HasStandardAttributes,
                                 standard_attr.model_base.HasId,
                                 base):
            collection_resource_map = {'collection_name': 'member_name'}
            tag_support = True

        with testtools.ExpectedException(RuntimeError):
            standard_attr.get_tag_resource_parent_map()


class StandardAttrAPIImapctTestCase(testlib_api.SqlTestCase):
    """Test case to determine if a resource has had new fields exposed."""

    def test_api_collections_are_expected(self):
        # NOTE to reviewers. If this test is being modified, it means the
        # resources being extended by standard attr extensions have changed.
        # Ensure that the patch has made this discoverable to API users.
        # This means a new extension for a new resource or a new extension
        # indicating that an existing resource now has standard attributes.
        # Ensure devref list of resources is updated at
        # doc/source/devref/api_extensions.rst
        expected = ['subnets', 'trunks', 'routers', 'segments',
                    'security_group_rules', 'networks', 'policies',
                    'subnetpools', 'ports', 'security_groups', 'floatingips',
                    'logs']
        self.assertEqual(
            set(expected),
            set(standard_attr.get_standard_attr_resource_model_map().keys())
        )

    def test_api_tag_support_is_expected(self):
        # NOTE: If this test is being modified, it means the resources for tag
        # support are extended. It changes tag support API. The API change
        # should be exposed in release note for API users. And also it should
        # be list as other tag support resources in doc/source/devref/tag.rst
        expected = ['subnets', 'trunks', 'routers', 'networks', 'policies',
                    'subnetpools', 'ports', 'security_groups', 'floatingips']
        self.assertEqual(
            set(expected),
            set(standard_attr.get_tag_resource_parent_map().keys())
        )


class StandardAttrRevisesBulkDeleteTestCase(testlib_api.SqlTestCase):

    def test_bulk_delete_protection(self):
        # security group rules increment security groups so they must not be
        # allowed to be deleted in bulk
        mm = standard_attr.get_standard_attr_resource_model_map()
        sg_rule_model = mm['security_group_rules']
        with testtools.ExpectedException(RuntimeError):
            ctx = context.get_admin_context()
            ctx.session.query(sg_rule_model).delete()
