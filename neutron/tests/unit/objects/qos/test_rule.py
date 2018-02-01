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
from neutron_lib.services.qos import constants as qos_consts

from oslo_utils import uuidutils
from oslo_versionedobjects import exception

from neutron.objects.qos import policy
from neutron.objects.qos import rule
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

    def test_should_apply_to_port_with_router_gw_port_and_net_policy(self):
        self._test_should_apply_to_port(
            rule_policy_id=POLICY_ID_B,
            port_policy_id=POLICY_ID_A,
            device_owner=constants.DEVICE_OWNER_ROUTER_GW,
            expected_result=False)

    def test_should_apply_to_port_with_router_gw_port_and_port_policy(self):
        self._test_should_apply_to_port(
            rule_policy_id=POLICY_ID_A,
            port_policy_id=POLICY_ID_A,
            device_owner=constants.DEVICE_OWNER_ROUTER_GW,
            expected_result=True)

    def test_should_apply_to_port_with_agent_gw_port_and_net_policy(self):
        self._test_should_apply_to_port(
            rule_policy_id=POLICY_ID_B,
            port_policy_id=POLICY_ID_A,
            device_owner=constants.DEVICE_OWNER_AGENT_GW,
            expected_result=False)

    def test_should_apply_to_port_with_agent_gw_port_and_port_policy(self):
        self._test_should_apply_to_port(
            rule_policy_id=POLICY_ID_A,
            port_policy_id=POLICY_ID_A,
            device_owner=constants.DEVICE_OWNER_AGENT_GW,
            expected_result=True)


class QosBandwidthLimitRuleObjectTestCase(test_base.BaseObjectIfaceTestCase):

    _test_class = rule.QosBandwidthLimitRule

    def test_to_dict_returns_type(self):
        obj = rule.QosBandwidthLimitRule(self.context, **self.db_objs[0])
        dict_ = obj.to_dict()
        self.assertEqual(qos_consts.RULE_TYPE_BANDWIDTH_LIMIT, dict_['type'])

    def test_bandwidth_limit_object_version_degradation(self):
        self.db_objs[0]['direction'] = constants.EGRESS_DIRECTION
        rule_obj = rule.QosBandwidthLimitRule(self.context, **self.db_objs[0])
        primitive_rule = rule_obj.obj_to_primitive('1.2')
        self.assertNotIn(
            "direction", primitive_rule['versioned_object.data'].keys())
        self.assertEqual(
            self.db_objs[0]['max_kbps'],
            primitive_rule['versioned_object.data']['max_kbps'])
        self.assertEqual(
            self.db_objs[0]['max_burst_kbps'],
            primitive_rule['versioned_object.data']['max_burst_kbps'])

        self.db_objs[0]['direction'] = constants.INGRESS_DIRECTION
        rule_obj = rule.QosBandwidthLimitRule(self.context, **self.db_objs[0])
        self.assertRaises(
            exception.IncompatibleObjectVersion,
            rule_obj.obj_to_primitive, '1.2')

    def test_duplicate_rules(self):
        policy_id = uuidutils.generate_uuid()
        ingress_rule_1 = rule.QosBandwidthLimitRule(
            self.context, qos_policy_id=policy_id,
            max_kbps=1000, max_burst=500,
            direction=constants.INGRESS_DIRECTION)
        ingress_rule_2 = rule.QosBandwidthLimitRule(
            self.context, qos_policy_id=policy_id,
            max_kbps=2000, max_burst=500,
            direction=constants.INGRESS_DIRECTION)
        egress_rule = rule.QosBandwidthLimitRule(
            self.context, qos_policy_id=policy_id,
            max_kbps=1000, max_burst=500,
            direction=constants.EGRESS_DIRECTION)
        dscp_rule = rule.QosDscpMarkingRule(
            self.context, qos_policy_id=policy_id, dscp_mark=16)
        self.assertTrue(ingress_rule_1.duplicates(ingress_rule_2))
        self.assertFalse(ingress_rule_1.duplicates(egress_rule))
        self.assertFalse(ingress_rule_1.duplicates(dscp_rule))


class QosBandwidthLimitRuleDbObjectTestCase(test_base.BaseDbObjectTestCase,
                                            testlib_api.SqlTestCase):

    _test_class = rule.QosBandwidthLimitRule

    def setUp(self):
        super(QosBandwidthLimitRuleDbObjectTestCase, self).setUp()

        # Prepare policy to be able to insert a rule
        for obj in self.db_objs:
            generated_qos_policy_id = obj['qos_policy_id']
            policy_obj = policy.QosPolicy(self.context,
                                          id=generated_qos_policy_id,
                                          project_id=uuidutils.generate_uuid())
            policy_obj.create()


class QosDscpMarkingRuleObjectTestCase(test_base.BaseObjectIfaceTestCase):

    _test_class = rule.QosDscpMarkingRule

    def test_dscp_object_version_degradation(self):
        dscp_rule = rule.QosDscpMarkingRule()

        self.assertRaises(exception.IncompatibleObjectVersion,
                     dscp_rule.obj_to_primitive, '1.0')

    def test_duplicate_rules(self):
        policy_id = uuidutils.generate_uuid()
        dscp_rule_1 = rule.QosDscpMarkingRule(
            self.context, qos_policy_id=policy_id, dscp_mark=16)
        dscp_rule_2 = rule.QosDscpMarkingRule(
            self.context, qos_policy_id=policy_id, dscp_mark=32)
        bw_limit_rule = rule.QosBandwidthLimitRule(
            self.context, qos_policy_id=policy_id,
            max_kbps=1000, max_burst=500,
            direction=constants.EGRESS_DIRECTION)
        self.assertTrue(dscp_rule_1.duplicates(dscp_rule_2))
        self.assertFalse(dscp_rule_1.duplicates(bw_limit_rule))


class QosDscpMarkingRuleDbObjectTestCase(test_base.BaseDbObjectTestCase,
                                         testlib_api.SqlTestCase):

    _test_class = rule.QosDscpMarkingRule

    def setUp(self):
        super(QosDscpMarkingRuleDbObjectTestCase, self).setUp()
        # Prepare policy to be able to insert a rule
        for obj in self.db_objs:
            generated_qos_policy_id = obj['qos_policy_id']
            policy_obj = policy.QosPolicy(self.context,
                                          id=generated_qos_policy_id,
                                          project_id=uuidutils.generate_uuid())
            policy_obj.create()


class QosMinimumBandwidthRuleObjectTestCase(test_base.BaseObjectIfaceTestCase):

    _test_class = rule.QosMinimumBandwidthRule

    def test_min_bw_object_version_degradation(self):
        min_bw_rule = rule.QosMinimumBandwidthRule()

        for version in ['1.0', '1.1']:
            self.assertRaises(exception.IncompatibleObjectVersion,
                              min_bw_rule.obj_to_primitive, version)

    def test_duplicate_rules(self):
        policy_id = uuidutils.generate_uuid()
        ingress_rule_1 = rule.QosMinimumBandwidthRule(
            self.context, qos_policy_id=policy_id,
            min_kbps=1000, direction=constants.INGRESS_DIRECTION)
        ingress_rule_2 = rule.QosMinimumBandwidthRule(
            self.context, qos_policy_id=policy_id,
            min_kbps=2000, direction=constants.INGRESS_DIRECTION)
        egress_rule = rule.QosMinimumBandwidthRule(
            self.context, qos_policy_id=policy_id,
            min_kbps=1000, direction=constants.EGRESS_DIRECTION)
        dscp_rule = rule.QosDscpMarkingRule(
            self.context, qos_policy_id=policy_id, dscp_mark=16)
        self.assertTrue(ingress_rule_1.duplicates(ingress_rule_2))
        self.assertFalse(ingress_rule_1.duplicates(egress_rule))
        self.assertFalse(ingress_rule_1.duplicates(dscp_rule))


class QosMinimumBandwidthRuleDbObjectTestCase(test_base.BaseDbObjectTestCase,
                                              testlib_api.SqlTestCase):

    _test_class = rule.QosMinimumBandwidthRule

    def setUp(self):
        super(QosMinimumBandwidthRuleDbObjectTestCase, self).setUp()
        # Prepare policy to be able to insert a rule
        for obj in self.db_objs:
            generated_qos_policy_id = obj['qos_policy_id']
            policy_obj = policy.QosPolicy(self.context,
                                          id=generated_qos_policy_id,
                                          project_id=uuidutils.generate_uuid())
            policy_obj.create()
