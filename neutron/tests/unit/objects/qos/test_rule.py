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

from neutron_lib import constants

from oslo_versionedobjects import exception

from neutron.objects.qos import policy
from neutron.objects.qos import rule
from neutron.services.qos import qos_consts
from neutron.tests import base as neutron_test_base
from neutron.tests.unit.objects import test_base
from neutron.tests.unit import testlib_api

POLICY_ID_A = 'policy-id-a'
POLICY_ID_B = 'policy-id-b'
DEVICE_OWNER_COMPUTE = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'fake'


class QosRuleObjectTestCase(neutron_test_base.BaseTestCase):

    def _test_should_apply_to_port(self, rule_policy_id, port_policy_id,
                                   device_owner, expected_result):
        test_rule = rule.QosRule(qos_policy_id=rule_policy_id)
        port = {qos_consts.QOS_POLICY_ID: port_policy_id,
                'device_owner': device_owner}
        self.assertEqual(expected_result, test_rule.should_apply_to_port(port))

    def test_should_apply_to_port_with_network_port_and_net_policy(self):
        self._test_should_apply_to_port(
            rule_policy_id=POLICY_ID_B,
            port_policy_id=POLICY_ID_A,
            device_owner=constants.DEVICE_OWNER_ROUTER_INTF,
            expected_result=False)

    def test_should_apply_to_port_with_network_port_and_only_net_policy(self):
        self._test_should_apply_to_port(
            rule_policy_id=POLICY_ID_B,
            port_policy_id=None,
            device_owner=constants.DEVICE_OWNER_ROUTER_INTF,
            expected_result=False)

    def test_should_apply_to_port_with_network_port_and_port_policy(self):
        self._test_should_apply_to_port(
            rule_policy_id=POLICY_ID_A,
            port_policy_id=POLICY_ID_A,
            device_owner=constants.DEVICE_OWNER_ROUTER_INTF,
            expected_result=True)

    def test_should_apply_to_port_with_compute_port_and_net_policy(self):
        # NOTE(ralonsoh): in this case the port has a port QoS policy; the
        # network QoS policy can't be applied.
        self._test_should_apply_to_port(
            rule_policy_id=POLICY_ID_B,
            port_policy_id=POLICY_ID_A,
            device_owner=DEVICE_OWNER_COMPUTE,
            expected_result=False)

    def test_should_apply_to_port_with_compute_port_and_only_net_policy(self):
        self._test_should_apply_to_port(
            rule_policy_id=POLICY_ID_B,
            port_policy_id=None,
            device_owner=DEVICE_OWNER_COMPUTE,
            expected_result=True)

    def test_should_apply_to_port_with_compute_port_and_port_policy(self):
        self._test_should_apply_to_port(
            rule_policy_id=POLICY_ID_A,
            port_policy_id=POLICY_ID_A,
            device_owner=DEVICE_OWNER_COMPUTE,
            expected_result=True)


class QosBandwidthLimitRuleObjectTestCase(test_base.BaseObjectIfaceTestCase):

    _test_class = rule.QosBandwidthLimitRule

    def test_to_dict_returns_type(self):
        obj = rule.QosBandwidthLimitRule(self.context, **self.db_objs[0])
        dict_ = obj.to_dict()
        self.assertEqual(qos_consts.RULE_TYPE_BANDWIDTH_LIMIT, dict_['type'])


class QosBandwidthLimitRuleDbObjectTestCase(test_base.BaseDbObjectTestCase,
                                            testlib_api.SqlTestCase):

    _test_class = rule.QosBandwidthLimitRule

    def setUp(self):
        super(QosBandwidthLimitRuleDbObjectTestCase, self).setUp()

        # Prepare policy to be able to insert a rule
        for obj in self.db_objs:
            generated_qos_policy_id = obj['qos_policy_id']
            policy_obj = policy.QosPolicy(self.context,
                                          id=generated_qos_policy_id)
            policy_obj.create()


class QosDscpMarkingRuleObjectTestCase(test_base.BaseObjectIfaceTestCase):

    _test_class = rule.QosDscpMarkingRule

    def test_dscp_object_version_degradation(self):
        dscp_rule = rule.QosDscpMarkingRule()

        self.assertRaises(exception.IncompatibleObjectVersion,
                     dscp_rule.obj_to_primitive, '1.0')

    def test_dscp_object_version(self):
        dscp_rule = rule.QosDscpMarkingRule()

        prim = dscp_rule.obj_to_primitive('1.1')

        self.assertTrue(prim)


class QosDscpMarkingRuleDbObjectTestCase(test_base.BaseDbObjectTestCase,
                                         testlib_api.SqlTestCase):

    _test_class = rule.QosDscpMarkingRule

    def setUp(self):
        super(QosDscpMarkingRuleDbObjectTestCase, self).setUp()
        # Prepare policy to be able to insert a rule
        for obj in self.db_objs:
            generated_qos_policy_id = obj['qos_policy_id']
            policy_obj = policy.QosPolicy(self.context,
                                          id=generated_qos_policy_id)
            policy_obj.create()


class QosMinimumBandwidthRuleObjectTestCase(test_base.BaseObjectIfaceTestCase):

    _test_class = rule.QosMinimumBandwidthRule

    def test_min_bw_object_version_degradation(self):
        min_bw_rule = rule.QosMinimumBandwidthRule()

        for version in ['1.0', '1.1']:
            self.assertRaises(exception.IncompatibleObjectVersion,
                              min_bw_rule.obj_to_primitive, version)

    def test_min_bw_object_version(self):
        min_bw_rule = rule.QosMinimumBandwidthRule()

        prim = min_bw_rule.obj_to_primitive('1.2')

        self.assertTrue(prim)


class QosMinimumBandwidthRuleDbObjectTestCase(test_base.BaseDbObjectTestCase,
                                              testlib_api.SqlTestCase):

    _test_class = rule.QosMinimumBandwidthRule

    def setUp(self):
        super(QosMinimumBandwidthRuleDbObjectTestCase, self).setUp()
        # Prepare policy to be able to insert a rule
        for obj in self.db_objs:
            generated_qos_policy_id = obj['qos_policy_id']
            policy_obj = policy.QosPolicy(self.context,
                                          id=generated_qos_policy_id)
            policy_obj.create()
