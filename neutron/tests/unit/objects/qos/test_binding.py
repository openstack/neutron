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
