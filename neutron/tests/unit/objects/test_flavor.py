# Copyright 2016 Intel Corporation.
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

from neutron.objects import flavor
from neutron.tests.unit.objects import test_base as obj_test_base
from neutron.tests.unit import testlib_api


class FlavorServiceProfileBindingIfaceObjectTestCase(
    obj_test_base.BaseObjectIfaceTestCase):

    _test_class = flavor.FlavorServiceProfileBinding


class FlavorServiceProfileBindingDbObjectTestCase(
    obj_test_base.BaseDbObjectTestCase, testlib_api.SqlTestCase):

    _test_class = flavor.FlavorServiceProfileBinding

    def setUp(self):
        super(FlavorServiceProfileBindingDbObjectTestCase, self).setUp()
        self.update_obj_fields(
            {'flavor_id': lambda: self._create_test_flavor_id(),
             'service_profile_id':
                 lambda: self._create_test_service_profile_id()})


class ServiceProfileIfaceObjectTestCase(obj_test_base.BaseObjectIfaceTestCase):

    _test_class = flavor.ServiceProfile


class ServiceProfileDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                                     testlib_api.SqlTestCase):

    _test_class = flavor.ServiceProfile

    def test_get_objects_queries_constant(self):
        # FIXME(electrocucaracha): There are no lazy loading for flavors
        # relationship in ServiceProfile model db disable this UT to avoid
        # failing
        pass


class FlavorIfaceObjectTestCase(obj_test_base.BaseObjectIfaceTestCase):

    _test_class = flavor.Flavor


class FlavorDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                             testlib_api.SqlTestCase):

    _test_class = flavor.Flavor

    def test_get_objects_queries_constant(self):
        # FIXME(electrocucaracha): There are no lazy loading for
        # service_profiles relationship in Flavor model db disable this UT to
        # avoid failing
        pass
