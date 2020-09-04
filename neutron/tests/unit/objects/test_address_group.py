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
from neutron.tests.unit import testlib_api


class AddressGroupIfaceObjectTestCase(
        obj_test_base.BaseObjectIfaceTestCase):

    _test_class = address_group.AddressGroup


class AddressGroupDbObjectTestCase(
        obj_test_base.BaseDbObjectTestCase, testlib_api.SqlTestCase):

    _test_class = address_group.AddressGroup

    def setUp(self):
        super(AddressGroupDbObjectTestCase, self).setUp()


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
