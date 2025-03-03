# Copyright (c) 2025 Red Hat Inc.
# All rights reserved.
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

from neutron_lib import constants as lib_consts
from neutron_lib import context
from neutron_lib.exceptions import qos as qos_exc
from neutron_lib.services.qos import constants as qos_consts

from neutron.objects.qos import policy
from neutron.objects.qos import qos_policy_validator
from neutron.objects.qos import rule
from neutron.tests.unit import testlib_api


class TestCheckBandwidthRuleConflict(testlib_api.SqlTestCase):

    def setUp(self):
        super().setUp()
        self.context = context.get_admin_context()
        self.qos_policy = policy.QosPolicy(self.context)
        self.qos_policy.create()
        self.max_bw_egress = 10000
        self.max_bw_rule = rule.QosBandwidthLimitRule(
            self.context, qos_policy_id=self.qos_policy.id,
            max_kbps=self.max_bw_egress,
            direction=lib_consts.EGRESS_DIRECTION)
        self.max_bw_rule.create()
        self.qos_policy.rules = [self.max_bw_rule]

    def test_check_bandwidth_rule_conflict_different_direction(self):
        rule_data = {qos_consts.DIRECTION: lib_consts.INGRESS_DIRECTION,
                     qos_consts.MIN_KBPS: self.max_bw_egress + 1}
        qos_policy_validator.check_bandwidth_rule_conflict(
            self.qos_policy, rule_data)

    def test_check_bandwidth_rule_conflict_same_direction(self):
        rule_data = {qos_consts.DIRECTION: lib_consts.EGRESS_DIRECTION,
                     qos_consts.MIN_KBPS: self.max_bw_egress + 1}
        self.assertRaises(qos_exc.QoSRuleParameterConflict,
                          qos_policy_validator.check_bandwidth_rule_conflict,
                          self.qos_policy, rule_data)
