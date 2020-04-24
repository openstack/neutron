# Copyright 2017 OpenStack Foundation
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

from unittest import mock

from oslo_utils import uuidutils

from neutron.agent.l3.extensions.qos import base as qos_base
from neutron.objects.qos import policy
from neutron.tests import base

_uuid = uuidutils.generate_uuid
TEST_POLICY = policy.QosPolicy(context=None,
                               name='test1', id=_uuid())
TEST_POLICY2 = policy.QosPolicy(context=None,
                                name='test2', id=_uuid())

TEST_RES_1 = "res1"
TEST_RES_2 = "res2"


class RateLimitMapsTestCase(base.BaseTestCase):

    def setUp(self):
        super(RateLimitMapsTestCase, self).setUp()
        self.policy_map = qos_base.RateLimitMaps("cache-lock")

    def test_update_policy(self):
        self.policy_map.update_policy(TEST_POLICY)
        self.assertEqual(TEST_POLICY,
                         self.policy_map.known_policies[TEST_POLICY.id])

    def _set_resources(self):
        self.policy_map.set_resource_policy(TEST_RES_1, TEST_POLICY)
        self.policy_map.set_resource_policy(TEST_RES_2, TEST_POLICY2)

    def test_set_resource_policy(self):
        self._set_resources()
        self.assertEqual(TEST_POLICY,
                         self.policy_map.known_policies[TEST_POLICY.id])
        self.assertIn(TEST_RES_1,
                      self.policy_map.qos_policy_resources[TEST_POLICY.id])

    def test_get_resource_policy(self):
        self._set_resources()
        self.assertEqual(TEST_POLICY,
                         self.policy_map.get_resource_policy(TEST_RES_1))
        self.assertEqual(TEST_POLICY2,
                         self.policy_map.get_resource_policy(TEST_RES_2))

    def test_get_resources(self):
        self._set_resources()
        self.assertEqual([TEST_RES_1],
                         list(self.policy_map.get_resources(TEST_POLICY)))

        self.assertEqual([TEST_RES_2],
                         list(self.policy_map.get_resources(TEST_POLICY2)))

    def test_clean_by_resource(self):
        self._set_resources()
        self.policy_map.clean_by_resource(TEST_RES_1)
        self.assertNotIn(TEST_POLICY.id, self.policy_map.known_policies)
        self.assertNotIn(TEST_RES_1, self.policy_map.resource_policies)
        self.assertIn(TEST_POLICY2.id, self.policy_map.known_policies)

    def test_clean_by_resource_for_unknown_resource(self):
        self.policy_map._clean_policy_info = mock.Mock()
        self.policy_map.clean_by_resource(TEST_RES_1)

        self.policy_map._clean_policy_info.assert_not_called()
