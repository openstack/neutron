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

from oslo_utils import uuidutils

from neutron.objects.qos import binding as qos_binding
from neutron.objects import router
from neutron.tests.unit.objects import test_base as obj_test_base
from neutron.tests.unit import testlib_api


class RouterRouteIfaceObjectTestCase(obj_test_base.BaseObjectIfaceTestCase):

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

    def _create_router(self, router_id, gw_port_id, project_id):
        r = router.Router(self.context,
                          id=router_id,
                          gw_port_id=gw_port_id,
                          project_id=project_id)
        r.create()

    def test_check_routers_not_owned_by_projects(self):
        for obj in self.obj_fields:
            self._create_router(router_id=obj['id'],
                                gw_port_id=obj['gw_port_id'],
                                project_id=obj['project_id'])
        obj = self.obj_fields[0]

        gw_port = obj['gw_port_id']
        project = obj['project_id']
        new_project = project

        gw_port_no_match = uuidutils.generate_uuid()
        project_no_match = uuidutils.generate_uuid()
        new_project_no_match = uuidutils.generate_uuid()

        # Check router match with gw_port BUT no projects
        router_exist = router.Router.check_routers_not_owned_by_projects(
            self.context,
            [gw_port],
            [project_no_match, new_project_no_match])
        self.assertTrue(router_exist)

        # Check router doesn't match with gw_port
        router_exist = router.Router.check_routers_not_owned_by_projects(
            self.context,
            [gw_port_no_match],
            [project])
        self.assertFalse(router_exist)

        # Check router match with gw_port AND project
        router_exist = router.Router.check_routers_not_owned_by_projects(
            self.context,
            [gw_port],
            [project, new_project_no_match])
        self.assertFalse(router_exist)

        # Check router match with gw_port AND new project
        router_exist = router.Router.check_routers_not_owned_by_projects(
            self.context,
            [gw_port],
            [project_no_match, new_project])
        self.assertFalse(router_exist)

        # Check router match with gw_port AND project AND new project
        router_exist = router.Router.check_routers_not_owned_by_projects(
            self.context,
            [gw_port],
            [project, new_project])
        self.assertFalse(router_exist)


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

    def test_qos_policy(self):
        _qos_policy_1 = self._create_test_qos_policy()
        _qos_policy_2 = self._create_test_qos_policy()

        self.obj_fields[0]['qos_policy_id'] = _qos_policy_1.id
        obj = self._test_class(
            self.context, **obj_test_base.remove_timestamps_from_fields(
                self.obj_fields[0], self._test_class.fields))
        obj.create()
        self.assertEqual(_qos_policy_1.id, obj.qos_policy_id)

        obj.qos_policy_id = _qos_policy_2.id
        obj.update()
        self.assertEqual(_qos_policy_2.id, obj.qos_policy_id)

        obj.qos_policy_id = None
        obj.update()
        self.assertIsNone(obj.qos_policy_id)

        obj.qos_policy_id = _qos_policy_1.id
        obj.update()
        fip_id = obj.id
        qos_fip_binding = qos_binding.QosPolicyFloatingIPBinding.get_objects(
            self.context, fip_id=fip_id)
        self.assertEqual(1, len(qos_fip_binding))
        self.assertEqual(_qos_policy_1.id, qos_fip_binding[0].policy_id)
        obj.delete()
        qos_fip_binding = qos_binding.QosPolicyFloatingIPBinding.get_objects(
            self.context, fip_id=fip_id)
        self.assertEqual([], qos_fip_binding)

    def test_v1_1_to_v1_0_drops_qos_policy_id(self):
        obj = self._make_object(self.obj_fields[0])
        obj_v1_0 = obj.obj_to_primitive(target_version='1.0')
        self.assertNotIn('qos_policy_id', obj_v1_0['versioned_object.data'])


class DvrFipGatewayPortAgentBindingTestCase(
        obj_test_base.BaseObjectIfaceTestCase):

    _test_class = router.DvrFipGatewayPortAgentBinding
