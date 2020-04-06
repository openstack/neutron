# Copyright (c) 2016 Intel Corporation.
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

from neutron_lib import constants as lib_constants

from neutron.objects import address_scope
from neutron.tests.unit.objects import test_base
from neutron.tests.unit.objects import test_rbac
from neutron.tests.unit import testlib_api


class AddressScopeIfaceObjectTestCase(test_base.BaseObjectIfaceTestCase):

    _test_class = address_scope.AddressScope


class AddressScopeDbObjectTestCase(test_base.BaseDbObjectTestCase,
                                   testlib_api.SqlTestCase):

    _test_class = address_scope.AddressScope


class AddressScopeRBACDbObjectTestCase(test_rbac.TestRBACObjectMixin,
                                       test_base.BaseDbObjectTestCase,
                                       testlib_api.SqlTestCase):

    _test_class = address_scope.AddressScopeRBAC

    def setUp(self):
        super(AddressScopeRBACDbObjectTestCase, self).setUp()
        for obj in self.db_objs:
            as_obj = address_scope.AddressScope(
                self.context,
                id=obj['object_id'],
                name="test_as_%s_%s" % (obj['object_id'], obj['project_id']),
                project_id=obj['project_id'],
                ip_version=lib_constants.IP_ALLOWED_VERSIONS[0],
            )
            as_obj.create()

    def _create_test_address_scope_rbac(self):
        self.objs[0].create()
        return self.objs[0]


class AddressScopeRBACIfaceObjectTestCase(test_rbac.TestRBACObjectMixin,
                                          test_base.BaseObjectIfaceTestCase):
    _test_class = address_scope.AddressScopeRBAC
