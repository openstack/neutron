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

    def test_attach_network_get_network_policy(self):
        obj = policy.QosPolicy(self.context, **self.db_obj)
        obj.create()

        # TODO(ihrachys): replace with network.create() once we get an object
        # implementation for networks
        network = db_api.create_object(self.context, models_v2.Network,
                                       {'name': 'test-network1'})

        policy_obj = policy.QosPolicy.get_network_policy(self.context,
                                                         network['id'])
        self.assertIsNone(policy_obj)

        # Now attach policy and repeat
        obj.attach_network(network['id'])

        policy_obj = policy.QosPolicy.get_network_policy(self.context,
                                                         network['id'])
        self.assertEqual(obj, policy_obj)

    def test_attach_port_get_port_policy(self):
        obj = policy.QosPolicy(self.context, **self.db_obj)
        obj.create()

        # TODO(ihrachys): replace with network.create() once we get an object
        # implementation for networks
        network = db_api.create_object(self.context, models_v2.Network,
                                       {'name': 'test-network1'})

        # TODO(ihrachys): replace with port.create() once we get an object
        # implementation for ports
        port = db_api.create_object(self.context, models_v2.Port,
                                    {'name': 'test-port1',
                                     'network_id': network['id'],
                                     'mac_address': 'fake_mac',
                                     'admin_state_up': True,
                                     'status': 'ACTIVE',
                                     'device_id': 'fake_device',
                                     'device_owner': 'fake_owner'})

        policy_obj = policy.QosPolicy.get_port_policy(self.context,
                                                      port['id'])
        self.assertIsNone(policy_obj)

        # Now attach policy and repeat
        obj.attach_port(port['id'])

        policy_obj = policy.QosPolicy.get_port_policy(self.context,
                                                      port['id'])
        self.assertEqual(obj, policy_obj)
