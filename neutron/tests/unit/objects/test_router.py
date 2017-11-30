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


from neutron.objects import router
from neutron.tests.unit.objects import test_base as obj_test_base
from neutron.tests.unit import testlib_api


class RouterRouteIfaceObjectTestCase(
    obj_test_base.BaseObjectIfaceTestCase):

    _test_class = router.RouterRoute


class RouterRouteDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                                  testlib_api.SqlTestCase):

    _test_class = router.RouterRoute

    def setUp(self):
        super(RouterRouteDbObjectTestCase, self).setUp()
        self.update_obj_fields(
            {'router_id': lambda: self._create_test_router_id()})


class RouterExtraAttrsIfaceObjTestCase(obj_test_base.
                                       BaseObjectIfaceTestCase):
    _test_class = router.RouterExtraAttributes


class RouterExtraAttrsDbObjTestCase(obj_test_base.BaseDbObjectTestCase,
                                    testlib_api.SqlTestCase):
    _test_class = router.RouterExtraAttributes

    def setUp(self):
        super(RouterExtraAttrsDbObjTestCase, self).setUp()
        self.update_obj_fields(
            {'router_id': lambda: self._create_test_router_id()})


class RouterIfaceObjectTestCase(obj_test_base.BaseObjectIfaceTestCase):

    _test_class = router.Router


class RouterDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                             testlib_api.SqlTestCase):

    _test_class = router.Router

    def setUp(self):
        super(RouterDbObjectTestCase, self).setUp()
        self.update_obj_fields(
            {'gw_port_id': lambda: self._create_test_port_id(),
             'flavor_id': lambda: self._create_test_flavor_id()})


class RouterPortIfaceObjectTestCase(obj_test_base.BaseObjectIfaceTestCase):

    _test_class = router.RouterPort


class RouterPortDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                                 testlib_api.SqlTestCase):

    _test_class = router.RouterPort

    def setUp(self):
        super(RouterPortDbObjectTestCase, self).setUp()
        self.update_obj_fields(
            {'router_id': lambda: self._create_test_router_id(),
             'port_id': lambda: self._create_test_port_id()})


class DVRMacAddressIfaceObjectTestCase(obj_test_base.BaseObjectIfaceTestCase):

    _test_class = router.DVRMacAddress


class DVRMacAddressDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                                    testlib_api.SqlTestCase):

    _test_class = router.DVRMacAddress


class FloatingIPIfaceObjectTestCase(obj_test_base.BaseObjectIfaceTestCase):

    _test_class = router.FloatingIP


class FloatingIPDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                                 testlib_api.SqlTestCase):

    _test_class = router.FloatingIP

    def setUp(self):
        super(FloatingIPDbObjectTestCase, self).setUp()
        self.update_obj_fields(
            {'floating_port_id': lambda: self._create_test_port_id(),
             'fixed_port_id': lambda: self._create_test_port_id(),
             'router_id': lambda: self._create_test_router_id()})
