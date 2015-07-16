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

from neutron.db import api as db_api
from neutron.db import models_v2
from neutron.objects.qos import policy
from neutron.objects.qos import rule
from neutron.tests.unit.objects import test_base
from neutron.tests.unit import testlib_api


class QosPolicyBaseTestCase(object):

    _test_class = policy.QosPolicy


class QosPolicyObjectTestCase(QosPolicyBaseTestCase,
                              test_base.BaseObjectIfaceTestCase):
    pass


class QosPolicyDbObjectTestCase(QosPolicyBaseTestCase,
                                test_base.BaseDbObjectTestCase,
                                testlib_api.SqlTestCase):

    def setUp(self):
        super(QosPolicyDbObjectTestCase, self).setUp()
        self._create_test_network()
        self._create_test_port(self._network)
        #TODO(QoS): move _create_test_policy here, as it's common
        #           to all. Now the base DB Object test case breaks
        #           that by introducing a duplicate object colliding
        #           on PK.

    def _create_test_policy(self):
        policy_obj = policy.QosPolicy(self.context, **self.db_obj)
        policy_obj.create()
        return policy_obj

    def _create_test_network(self):
        # TODO(ihrachys): replace with network.create() once we get an object
        # implementation for networks
        self._network = db_api.create_object(self.context, models_v2.Network,
                                             {'name': 'test-network1'})

    def _create_test_port(self, network):
        # TODO(ihrachys): replace with port.create() once we get an object
        # implementation for ports
        self._port = db_api.create_object(self.context, models_v2.Port,
                                          {'name': 'test-port1',
                                           'network_id': network['id'],
                                           'mac_address': 'fake_mac',
                                           'admin_state_up': True,
                                           'status': 'ACTIVE',
                                           'device_id': 'fake_device',
                                           'device_owner': 'fake_owner'})

    #TODO(QoS): give a thought on checking detach/attach for invalid values.
    def test_attach_network_get_network_policy(self):

        obj = self._create_test_policy()

        policy_obj = policy.QosPolicy.get_network_policy(self.context,
                                                         self._network['id'])
        self.assertIsNone(policy_obj)

        # Now attach policy and repeat
        obj.attach_network(self._network['id'])

        policy_obj = policy.QosPolicy.get_network_policy(self.context,
                                                         self._network['id'])
        self.assertEqual(obj, policy_obj)

    def test_attach_port_get_port_policy(self):

        obj = self._create_test_policy()

        policy_obj = policy.QosPolicy.get_network_policy(self.context,
                                                         self._network['id'])

        self.assertIsNone(policy_obj)

        # Now attach policy and repeat
        obj.attach_port(self._port['id'])

        policy_obj = policy.QosPolicy.get_port_policy(self.context,
                                                      self._port['id'])
        self.assertEqual(obj, policy_obj)

    def test_detach_port(self):
        obj = self._create_test_policy()
        obj.attach_port(self._port['id'])
        obj.detach_port(self._port['id'])

        policy_obj = policy.QosPolicy.get_port_policy(self.context,
                                                      self._port['id'])
        self.assertIsNone(policy_obj)

    def test_detach_network(self):
        obj = self._create_test_policy()
        obj.attach_network(self._network['id'])
        obj.detach_network(self._network['id'])

        policy_obj = policy.QosPolicy.get_network_policy(self.context,
                                                         self._network['id'])
        self.assertIsNone(policy_obj)

    def test_synthetic_rule_fields(self):
        obj = policy.QosPolicy(self.context, **self.db_obj)
        obj.create()

        rule_fields = self.get_random_fields(
            obj_cls=rule.QosBandwidthLimitRule)
        rule_fields['qos_policy_id'] = obj.id
        rule_fields['tenant_id'] = obj.tenant_id

        rule_obj = rule.QosBandwidthLimitRule(self.context, **rule_fields)
        rule_obj.create()

        obj = policy.QosPolicy.get_by_id(self.context, obj.id)
        self.assertEqual([rule_obj], obj.bandwidth_limit_rules)
