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

from neutron.objects.qos import policy
from neutron.objects.qos import rule
from neutron.tests.unit.objects import test_base
from neutron.tests.unit import testlib_api


class QosBandwidthLimitRuleObjectTestCase(test_base.BaseObjectIfaceTestCase):

    _test_class = rule.QosBandwidthLimitRule


class QosBandwidthLimitRuleDbObjectTestCase(test_base.BaseDbObjectTestCase,
                                            testlib_api.SqlTestCase):

    _test_class = rule.QosBandwidthLimitRule

    def setUp(self):
        super(QosBandwidthLimitRuleDbObjectTestCase, self).setUp()

        # Prepare policy to be able to insert a rule
        generated_qos_policy_id = self.db_obj['qos_policy_id']
        policy_obj = policy.QosPolicy(self.context,
                                      id=generated_qos_policy_id)
        policy_obj.create()
