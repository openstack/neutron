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

from neutron.objects import address_group
from neutron.tests.unit.objects import test_base as obj_test_base
from neutron.tests.unit.objects import test_rbac
from neutron.tests.unit import testlib_api


class AddressGroupIfaceObjectTestCase(
        obj_test_base.BaseObjectIfaceTestCase):

    _test_class = address_group.AddressGroup


class AddressGroupDbObjectTestCase(
        obj_test_base.BaseDbObjectTestCase, testlib_api.SqlTestCase):

    _test_class = address_group.AddressGroup

    def setUp(self):
        super(AddressGroupDbObjectTestCase, self).setUp()

    def _create_test_address_group(self):
        self.objs[0].create()
        return self.objs[0]

    def test_object_version_degradation_1_1_to_1_0_no_standard_attrs(self):
        ag_obj = self._create_test_address_group()
        ag_obj_1_0 = ag_obj.obj_to_primitive('1.0')
        self.assertNotIn('revision_number',
                         ag_obj_1_0['versioned_object.data'])
        self.assertNotIn('created_at',
                         ag_obj_1_0['versioned_object.data'])
        self.assertNotIn('updated_at',
                         ag_obj_1_0['versioned_object.data'])
        # description filed was added to initial version separately
        self.assertIn('description',
                      ag_obj_1_0['versioned_object.data'])

    def test_object_version_degradation_1_2_to_1_1_no_shared(self):
        ag_obj = self._create_test_address_group()
        ag_obj_1_1 = ag_obj.obj_to_primitive('1.1')
        self.assertNotIn('shared', ag_obj_1_1['versioned_object.data'])


class AddressGroupRBACDbObjectTestCase(test_rbac.TestRBACObjectMixin,
                                       obj_test_base.BaseDbObjectTestCase,
                                       testlib_api.SqlTestCase):

    _test_class = address_group.AddressGroupRBAC

    def setUp(self):
        super(AddressGroupRBACDbObjectTestCase, self).setUp()
        for obj in self.db_objs:
            ag_obj = address_group.AddressGroup(self.context,
                                                id=obj['object_id'],
                                                project_id=obj['project_id'])
            ag_obj.create()

    def _create_test_address_group_rbac(self):
        self.objs[0].create()
        return self.objs[0]


class AddressGroupRBACIfaceObjectTestCase(
        test_rbac.TestRBACObjectMixin, obj_test_base.BaseObjectIfaceTestCase):

    _test_class = address_group.AddressGroupRBAC


class AddressAssociationIfaceObjectTestCase(
        obj_test_base.BaseObjectIfaceTestCase):

    _test_class = address_group.AddressAssociation


class AddressAssociationObjectTestCase(
        obj_test_base.BaseDbObjectTestCase, testlib_api.SqlTestCase):

    _test_class = address_group.AddressAssociation

    def setUp(self):
        super(AddressAssociationObjectTestCase, self).setUp()
        self.update_obj_fields(
            {
                'address_group_id':
                    lambda: self._create_test_address_group_id()
            })
