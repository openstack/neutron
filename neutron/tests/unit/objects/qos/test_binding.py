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

from neutron.objects.qos import binding
from neutron.objects import router
from neutron.tests.unit.objects import test_base
from neutron.tests.unit import testlib_api


class _QosPolicyBindingMixinTestCase(object):

    def test_get_bound_ids(self):
        [obj.create() for obj in self.objs]
        for obj in self.objs:
            obj_ids = obj.get_bound_ids(self.context, obj.policy_id)
            self.assertEqual(1, len(obj_ids))
            self.assertEqual(obj[obj.__class__._bound_model_id.name],
                             obj_ids[0])


class QosPolicyPortBindingObjectTestCase(test_base.BaseObjectIfaceTestCase):

    _test_class = binding.QosPolicyPortBinding


class QosPolicyPortBindingDbObjectTestCase(test_base.BaseDbObjectTestCase,
                                           testlib_api.SqlTestCase,
                                           _QosPolicyBindingMixinTestCase):

    _test_class = binding.QosPolicyPortBinding

    def setUp(self):
        super(QosPolicyPortBindingDbObjectTestCase, self).setUp()
        network_id = self._create_test_network_id()
        for db_obj in self.db_objs:
            self._create_test_qos_policy(id=db_obj['policy_id'])
            self._create_test_port(network_id=network_id,
                                   id=db_obj['port_id'])


class QosPolicyNetworkBindingObjectTestCase(test_base.BaseObjectIfaceTestCase):

    _test_class = binding.QosPolicyNetworkBinding


class QosPolicyNetworkBindingDbObjectTestCase(test_base.BaseDbObjectTestCase,
                                              testlib_api.SqlTestCase,
                                              _QosPolicyBindingMixinTestCase):

    _test_class = binding.QosPolicyNetworkBinding

    def setUp(self):
        super(QosPolicyNetworkBindingDbObjectTestCase, self).setUp()
        for db_obj in self.db_objs:
            self._create_test_qos_policy(id=db_obj['policy_id'])
            self._create_test_network(network_id=db_obj['network_id'])


class QosPolicyFloatingIPBindingObjectTestCase(
        test_base.BaseObjectIfaceTestCase):

    _test_class = binding.QosPolicyFloatingIPBinding


class QosPolicyFloatingIPBindingDbObjectTestCase(
        test_base.BaseDbObjectTestCase,
        testlib_api.SqlTestCase,
        _QosPolicyBindingMixinTestCase):

    _test_class = binding.QosPolicyFloatingIPBinding

    def setUp(self):
        super(QosPolicyFloatingIPBindingDbObjectTestCase, self).setUp()
        for db_obj in self.db_objs:
            self._create_test_qos_policy(id=db_obj['policy_id'])
            self._create_test_fip_id(fip_id=db_obj['fip_id'])


class QosPolicyRouterGatewayIPBindingObjectTestCase(
        test_base.BaseObjectIfaceTestCase):

    _test_class = binding.QosPolicyRouterGatewayIPBinding


class QosPolicyRouterGatewayIPBindingDbObjectTestCase(
        test_base.BaseDbObjectTestCase,
        testlib_api.SqlTestCase,
        _QosPolicyBindingMixinTestCase):

    _test_class = binding.QosPolicyRouterGatewayIPBinding

    def setUp(self):
        super(QosPolicyRouterGatewayIPBindingDbObjectTestCase, self).setUp()
        for db_obj in self.db_objs:
            self._create_test_qos_policy(id=db_obj['policy_id'])
            self._create_test_router_id(router_id=db_obj['router_id'])

    def test_get_routers_by_network_id(self):
        qos_policy_router_obj = self._create_test_qos_policy()
        qos_policy_net_obj = self._create_test_qos_policy()
        # External network 1, no QoS policy
        ext_network_id_1 = self._create_external_network_id()
        gw_port_id_1a = self._create_test_port_id(network_id=ext_network_id_1)
        gw_port_id_1b = self._create_test_port_id(network_id=ext_network_id_1)
        # External network 2, "qos_policy_network" assigned
        ext_network_id_2 = self._create_external_network_id(
            qos_policy_id=qos_policy_net_obj.id)
        gw_port_id_2a = self._create_test_port_id(network_id=ext_network_id_2)
        gw_port_id_2b = self._create_test_port_id(network_id=ext_network_id_2)

        # Router 1: no GW
        self._create_test_router_id(name='router1')

        # Router 2: GW assigned, no router QoS, not public network QoS
        router2 = self._create_test_router_id(name='router2')
        router2_obj = router.Router.get_object(self.context, id=router2)
        router2_obj.gw_port_id = gw_port_id_1a
        router2_obj.update()

        # Router 3: GW assigned, router QoS, not public network QoS
        router3 = self._create_test_router_id(name='router3')
        router3_obj = router.Router.get_object(self.context, id=router3)
        router3_obj.gw_port_id = gw_port_id_1b
        router3_obj.qos_policy_id = qos_policy_router_obj.id
        router3_obj.update()

        # Router 4: GW assigned, no router QoS, public network with QoS
        router4 = self._create_test_router_id(name='router4')
        router4_obj = router.Router.get_object(self.context, id=router4)
        router4_obj.gw_port_id = gw_port_id_2a
        router4_obj.update()

        # Router 5: GW assigned, router QoS, public network with QoS
        router5 = self._create_test_router_id(name='router5')
        router5_obj = router.Router.get_object(self.context, id=router5)
        router5_obj.gw_port_id = gw_port_id_2b
        router5_obj.qos_policy_id = qos_policy_router_obj.id
        router5_obj.update()

        # Check that only router3 and router5 have
        # "QosPolicyRouterGatewayIPBinding" related registers.
        qos_gw_binds = self._test_class.get_objects(self.context)
        self.assertEqual(2, len(qos_gw_binds))
        router_ids = [qos_gw_bind.router_id for qos_gw_bind in qos_gw_binds]
        self.assertEqual(sorted([router3, router5]), sorted(router_ids))

        result = self._test_class.get_routers_by_network_id(
            self.context, ext_network_id_1, policy_id=None)
        self.assertEqual([router2], [r.id for r in result])

        result = self._test_class.get_routers_by_network_id(
            self.context, ext_network_id_1, policy_id=qos_policy_router_obj.id)
        self.assertEqual([router3], [r.id for r in result])

        result = self._test_class.get_routers_by_network_id(
            self.context, ext_network_id_1, policy_id=qos_policy_net_obj.id)
        self.assertEqual([], [r.id for r in result])

        result = self._test_class.get_routers_by_network_id(
            self.context, ext_network_id_2, policy_id=None)
        self.assertEqual([router4], [r.id for r in result])

        result = self._test_class.get_routers_by_network_id(
            self.context, ext_network_id_2, policy_id=qos_policy_router_obj.id)
        self.assertEqual([router5], [r.id for r in result])

        result = self._test_class.get_routers_by_network_id(
            self.context, ext_network_id_2, policy_id=qos_policy_net_obj.id)
        self.assertEqual([], [r.id for r in result])
