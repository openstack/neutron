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

import mock
from neutron_lib import constants as lib_const
from neutron_lib import context
from neutron_lib import rpc as n_rpc
from neutron_lib.services.qos import constants as qos_consts
from oslo_utils import uuidutils

from neutron.agent.l3 import agent as l3_agent
from neutron.agent.l3.extensions.qos import fip as fip_qos
from neutron.agent.l3 import l3_agent_extension_api as l3_ext_api
from neutron.agent.l3 import router_info as l3router
from neutron.api.rpc.callbacks.consumer import registry
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import resources_rpc
from neutron.objects.qos import policy
from neutron.objects.qos import rule
from neutron.tests import base
from neutron.tests.unit.agent.l3 import test_agent

_uuid = uuidutils.generate_uuid

TEST_QOS_FIP = "3.3.3.3"

TEST_FIP = "1.1.1.1"
TEST_FIP2 = "2.2.2.2"

HOSTNAME = 'myhost'


class QosExtensionBaseTestCase(test_agent.BasicRouterOperationsFramework):

    def setUp(self):
        super(QosExtensionBaseTestCase, self).setUp()

        self.fip_qos_ext = fip_qos.FipQosAgentExtension()
        self.context = context.get_admin_context()
        self.connection = mock.Mock()

        self.policy = policy.QosPolicy(context=None,
                                       name='test1', id=_uuid())
        self.ingress_rule = (
            rule.QosBandwidthLimitRule(context=None, id=_uuid(),
                                       qos_policy_id=self.policy.id,
                                       max_kbps=1111,
                                       max_burst_kbps=2222,
                                       direction=lib_const.INGRESS_DIRECTION))
        self.egress_rule = (
            rule.QosBandwidthLimitRule(context=None, id=_uuid(),
                                       qos_policy_id=self.policy.id,
                                       max_kbps=3333,
                                       max_burst_kbps=4444,
                                       direction=lib_const.EGRESS_DIRECTION))
        self.policy.rules = [self.ingress_rule, self.egress_rule]

        self.new_ingress_rule = (
            rule.QosBandwidthLimitRule(context=None, id=_uuid(),
                                       qos_policy_id=self.policy.id,
                                       max_kbps=5555,
                                       max_burst_kbps=6666,
                                       direction=lib_const.INGRESS_DIRECTION))
        self.ingress_rule_only_has_max_kbps = (
            rule.QosBandwidthLimitRule(context=None, id=_uuid(),
                                       qos_policy_id=self.policy.id,
                                       max_kbps=5555,
                                       max_burst_kbps=0,
                                       direction=lib_const.INGRESS_DIRECTION))

        self.policy2 = policy.QosPolicy(context=None,
                                        name='test2', id=_uuid())
        self.policy2.rules = [self.ingress_rule]

        self.policy3 = policy.QosPolicy(context=None,
                                        name='test3', id=_uuid())
        self.policy3.rules = [self.egress_rule]

        self.policy4 = policy.QosPolicy(context=None,
                                        name='test4', id=_uuid())
        self.dscp = rule.QosDscpMarkingRule(context=None, id=_uuid(),
                                            qos_policy_id=self.policy4.id,
                                            dscp_mark=32)
        self.dscp.obj_reset_changes()
        self.policy4.rules = [self.dscp]

        self.qos_policies = {self.policy.id: self.policy,
                             self.policy2.id: self.policy2,
                             self.policy3.id: self.policy3,
                             self.policy4.id: self.policy4}

        self.agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self.ex_gw_port = {'id': _uuid()}
        self.fip = {'id': _uuid(),
                    'floating_ip_address': TEST_QOS_FIP,
                    'fixed_ip_address': '192.168.0.1',
                    'floating_network_id': _uuid(),
                    'port_id': _uuid(),
                    'host': HOSTNAME,
                    'qos_policy_id': self.policy.id}
        self.router_id = _uuid()
        self.router = {'id': self.router_id,
                       'gw_port': self.ex_gw_port,
                       'ha': False,
                       'distributed': False,
                       lib_const.FLOATINGIP_KEY: [self.fip]}
        self.router_info = l3router.RouterInfo(self.agent, self.router_id,
                                               self.router, **self.ri_kwargs)
        self.router_info.ex_gw_port = self.ex_gw_port
        self.agent.router_info[self.router_id] = self.router_info

        def _mock_get_router_info(router_id):
            return self.router_info

        self.get_router_info = mock.patch(
            'neutron.agent.l3.l3_agent_extension_api.'
            'L3AgentExtensionAPI.get_router_info').start()
        self.get_router_info.side_effect = _mock_get_router_info

        self.agent_api = l3_ext_api.L3AgentExtensionAPI(None, None)
        self.fip_qos_ext.consume_api(self.agent_api)


class FipQosExtensionInitializeTestCase(QosExtensionBaseTestCase):

    @mock.patch.object(registry, 'register')
    @mock.patch.object(resources_rpc, 'ResourcesPushRpcCallback')
    def test_initialize_subscribed_to_rpc(self, rpc_mock, subscribe_mock):
        with mock.patch.object(n_rpc, 'Connection',
                        return_value=self.connection) as create_connection:
            self.fip_qos_ext.initialize(
                self.connection, lib_const.L3_AGENT_MODE)
            create_connection.assert_has_calls([mock.call()])
            self.connection.create_consumer.assert_has_calls(
                [mock.call(
                     resources_rpc.resource_type_versioned_topic(
                         resources.QOS_POLICY),
                     [rpc_mock()],
                     fanout=True)]
            )
            subscribe_mock.assert_called_with(mock.ANY, resources.QOS_POLICY)


class FipQosExtensionTestCase(QosExtensionBaseTestCase):

    def setUp(self):
        super(FipQosExtensionTestCase, self).setUp()
        self.fip_qos_ext.initialize(
            self.connection, lib_const.L3_AGENT_MODE)
        self._set_pull_mock()

    def _set_pull_mock(self):

        def _pull_mock(context, resource_type, resource_id):
            return self.qos_policies[resource_id]

        self.pull = mock.patch(
            'neutron.api.rpc.handlers.resources_rpc.'
            'ResourcesPullRpcApi.pull').start()
        self.pull.side_effect = _pull_mock

    def _test_new_fip_add(self, func):
        tc_wrapper = mock.Mock()
        with mock.patch.object(self.fip_qos_ext, '_get_tc_wrapper',
                               return_value=tc_wrapper):
            func(self.context, self.router)
            tc_wrapper.set_ip_rate_limit.assert_has_calls(
                [mock.call(lib_const.INGRESS_DIRECTION,
                           TEST_QOS_FIP, 1111, 2222),
                 mock.call(lib_const.EGRESS_DIRECTION,
                           TEST_QOS_FIP, 3333, 4444)],
                any_order=True)

    def test_add_router(self):
        self._test_new_fip_add(self.fip_qos_ext.add_router)

    def test_update_router(self):
        self._test_new_fip_add(self.fip_qos_ext.update_router)

    def test_update_router_fip_policy_changed(self):
        tc_wrapper = mock.Mock()
        with mock.patch.object(self.fip_qos_ext, '_get_tc_wrapper',
                               return_value=tc_wrapper):
            self.fip_qos_ext.update_router(self.context, self.router)
            tc_wrapper.set_ip_rate_limit.assert_has_calls(
                [mock.call(lib_const.INGRESS_DIRECTION,
                           TEST_QOS_FIP, 1111, 2222),
                 mock.call(lib_const.EGRESS_DIRECTION,
                           TEST_QOS_FIP, 3333, 4444)],
                any_order=True)
            # the policy of floating IP has been changed to
            # which only has one egress rule
            self.fip[qos_consts.QOS_POLICY_ID] = self.policy3.id
            self.fip_qos_ext.update_router(self.context, self.router)
            tc_wrapper.clear_ip_rate_limit.assert_has_calls(
                [mock.call(lib_const.INGRESS_DIRECTION,
                           TEST_QOS_FIP)])

    def test_update_router_fip_policy_changed_to_none(self):
        tc_wrapper = mock.Mock()
        with mock.patch.object(self.fip_qos_ext, '_get_tc_wrapper',
                               return_value=tc_wrapper):
            self.fip_qos_ext.update_router(self.context, self.router)
            tc_wrapper.set_ip_rate_limit.assert_has_calls(
                [mock.call(lib_const.INGRESS_DIRECTION,
                           TEST_QOS_FIP, 1111, 2222),
                 mock.call(lib_const.EGRESS_DIRECTION,
                           TEST_QOS_FIP, 3333, 4444)],
                any_order=True)
            # floating IP remove the qos_policy bonding
            self.fip[qos_consts.QOS_POLICY_ID] = None
            self.fip_qos_ext.update_router(self.context, self.router)
            tc_wrapper.clear_ip_rate_limit.assert_has_calls(
                [mock.call(lib_const.INGRESS_DIRECTION,
                           TEST_QOS_FIP),
                 mock.call(lib_const.EGRESS_DIRECTION,
                           TEST_QOS_FIP)],
                any_order=True)

    def test__process_update_policy(self):
        tc_wrapper = mock.Mock()
        with mock.patch.object(self.fip_qos_ext, '_get_tc_wrapper',
                               return_value=tc_wrapper):
            self.fip_qos_ext.update_router(self.context, self.router)
            tc_wrapper.set_ip_rate_limit.assert_has_calls(
                [mock.call(lib_const.INGRESS_DIRECTION,
                           TEST_QOS_FIP, 1111, 2222),
                 mock.call(lib_const.EGRESS_DIRECTION,
                           TEST_QOS_FIP, 3333, 4444)],
                any_order=True)
            # the rules of floating IP policy has been changed
            self.fip_qos_ext._policy_rules_modified = mock.Mock(
                return_value=True)
            self.policy.rules = [self.new_ingress_rule, self.egress_rule]
            self.fip_qos_ext._process_update_policy(self.policy)
            tc_wrapper.set_ip_rate_limit.assert_has_calls(
                [mock.call(lib_const.INGRESS_DIRECTION,
                           TEST_QOS_FIP, 5555, 6666)])

    def _test_qos_policy_scenarios(self, fip_removed=True,
                                   qos_rules_removed=False):

        tc_wrapper = mock.Mock()
        with mock.patch.object(self.fip_qos_ext, '_get_tc_wrapper',
                               return_value=tc_wrapper):
            self.fip_qos_ext.update_router(self.context, self.router)
            tc_wrapper.set_ip_rate_limit.assert_has_calls(
                [mock.call(lib_const.INGRESS_DIRECTION,
                           TEST_QOS_FIP, 1111, 2222),
                 mock.call(lib_const.EGRESS_DIRECTION,
                           TEST_QOS_FIP, 3333, 4444)],
                any_order=True)
            if fip_removed:
                # floating IP dissociated, then it does not belong to
                # this router
                self.router[lib_const.FLOATINGIP_KEY] = []
            if qos_rules_removed:
                self.policy.rules = []
            self.fip_qos_ext.update_router(self.context, self.router)
            tc_wrapper.clear_ip_rate_limit.assert_has_calls(
                [mock.call(lib_const.INGRESS_DIRECTION,
                           TEST_QOS_FIP),
                 mock.call(lib_const.EGRESS_DIRECTION,
                           TEST_QOS_FIP)],
                any_order=True)

    def test_delete_router(self):
        tc_wrapper = mock.Mock()
        with mock.patch.object(self.fip_qos_ext, '_get_tc_wrapper',
                               return_value=tc_wrapper):
            self.fip_qos_ext.update_router(self.context, self.router)
            tc_wrapper.set_ip_rate_limit.assert_has_calls(
                [mock.call(lib_const.INGRESS_DIRECTION,
                           TEST_QOS_FIP, 1111, 2222),
                 mock.call(lib_const.EGRESS_DIRECTION,
                           TEST_QOS_FIP, 3333, 4444)],
                any_order=True)
            self.fip_qos_ext.delete_router(self.context, self.router)
            self.assertIsNone(
                self.fip_qos_ext.fip_qos_map.router_floating_ips.get(
                    self.router_id))
            self.assertIsNone(
                self.fip_qos_ext.fip_qos_map.ingress_ratelimits.get(
                    TEST_QOS_FIP))
            self.assertIsNone(
                self.fip_qos_ext.fip_qos_map.egress_ratelimits.get(
                    TEST_QOS_FIP))
            self.assertIsNone(
                self.fip_qos_ext.fip_qos_map.get_resource_policy(
                    TEST_QOS_FIP))

    def test_update_router_fip_removed(self):
        self._test_qos_policy_scenarios()

    def test_fip_qos_changed_to_none(self):
        self._test_qos_policy_scenarios(qos_rules_removed=True)

    def _test_only_one_direction_rule(self, func, policy, direction):
        tc_wrapper = mock.Mock()
        with mock.patch.object(
                self.fip_qos_ext.resource_rpc, 'pull',
                return_value=policy):
            with mock.patch.object(self.fip_qos_ext, '_get_tc_wrapper',
                                   return_value=tc_wrapper):
                func(self.context, self.router)
                if direction == lib_const.INGRESS_DIRECTION:
                    calls = [mock.call(lib_const.INGRESS_DIRECTION,
                                       TEST_QOS_FIP, 1111, 2222)]
                else:
                    calls = [mock.call(lib_const.EGRESS_DIRECTION,
                                       TEST_QOS_FIP, 3333, 4444)]
                tc_wrapper.set_ip_rate_limit.assert_has_calls(calls)

    def test_add_router_only_ingress(self):
        self._test_only_one_direction_rule(self.fip_qos_ext.add_router,
                                           self.policy2,
                                           lib_const.INGRESS_DIRECTION)

    def test_add_router_only_egress(self):
        self._test_only_one_direction_rule(self.fip_qos_ext.add_router,
                                           self.policy3,
                                           lib_const.EGRESS_DIRECTION)

    def test_update_router_only_ingress(self):
        self._test_only_one_direction_rule(self.fip_qos_ext.update_router,
                                           self.policy2,
                                           lib_const.INGRESS_DIRECTION)

    def test_update_router_only_egress(self):
        self._test_only_one_direction_rule(self.fip_qos_ext.update_router,
                                           self.policy3,
                                           lib_const.EGRESS_DIRECTION)

    def test_rule_only_has_max_kbps(self):
        tc_wrapper = mock.Mock()
        with mock.patch.object(self.fip_qos_ext, '_get_tc_wrapper',
                               return_value=tc_wrapper):
            self.fip_qos_ext.update_router(self.context, self.router)
            tc_wrapper.set_ip_rate_limit.assert_has_calls(
                [mock.call(lib_const.INGRESS_DIRECTION,
                           TEST_QOS_FIP, 1111, 2222),
                 mock.call(lib_const.EGRESS_DIRECTION,
                           TEST_QOS_FIP, 3333, 4444)],
                any_order=True)
            # policy ingress rule changed to only has one max_kbps value
            self.policy.rules = [self.ingress_rule_only_has_max_kbps,
                                 self.egress_rule]
            self.fip_qos_ext.update_router(self.context, self.router)
            tc_wrapper.set_ip_rate_limit.assert_has_calls(
                [mock.call(lib_const.INGRESS_DIRECTION,
                           TEST_QOS_FIP, 5555, 0)])

    def test_qos_policy_has_no_bandwidth_limit_rule(self):
        tc_wrapper = mock.Mock()
        with mock.patch.object(self.fip_qos_ext, '_get_tc_wrapper',
                               return_value=tc_wrapper):
            self.fip['qos_policy_id'] = self.policy4.id
            self.fip_qos_ext.add_router(self.context, self.router)
            tc_wrapper.set_ip_rate_limit.assert_not_called()

    def _test_process_ip_rates(self, with_cache):
        rates = {'egress': {'rate': 333, 'burst': 444},
                 'ingress': {'rate': 111, 'burst': 222}}
        fip = '123.123.123.123'
        device = mock.Mock()
        tc_wrapper = mock.Mock()
        with mock.patch.object(
                self.fip_qos_ext, '_get_tc_wrapper',
                return_value=tc_wrapper) as get_tc_wrapper:
            with mock.patch.object(
                    self.fip_qos_ext, 'process_ip_rate_limit') as process_ip:
                self.fip_qos_ext.process_ip_rates(
                    fip, device, rates, with_cache=with_cache)
                if with_cache:
                    self.assertEqual(2, process_ip.call_count)
                else:
                    self.assertEqual(2, get_tc_wrapper.call_count)
                    self.assertEqual(
                        2, tc_wrapper.set_ip_rate_limit.call_count)

    def test_process_ip_rates_with_cache(self):
        self._test_process_ip_rates(with_cache=True)

    def test_process_ip_rates_without_cache(self):
        self._test_process_ip_rates(with_cache=False)


class RouterFipRateLimitMapsTestCase(base.BaseTestCase):

    def setUp(self):
        super(RouterFipRateLimitMapsTestCase, self).setUp()
        self.policy_map = fip_qos.RouterFipRateLimitMaps()

    def test_find_fip_router_id(self):
        router_id = _uuid()
        self.policy_map.router_floating_ips[router_id] = set([TEST_FIP,
                                                              TEST_FIP2])
        self.assertIsNone(self.policy_map.find_fip_router_id("8.8.8.8"))
        self.assertEqual(router_id,
                         self.policy_map.find_fip_router_id(TEST_FIP))

    def test_get_router_floating_ips(self):
        router_id = _uuid()
        test_ips = [TEST_FIP, TEST_FIP2]
        self.policy_map.router_floating_ips[router_id] = set([TEST_FIP,
                                                              TEST_FIP2])
        get_ips = self.policy_map.get_router_floating_ips(router_id)
        self.assertEqual(len(test_ips), len(get_ips))

    def test_remove_fip_ratelimit_cache(self):
        fip = "1.1.1.1"
        self.policy_map.set_fip_ratelimit_cache(
            "ingress", fip, 100, 200)
        self.policy_map.set_fip_ratelimit_cache(
            "egress", fip, 100, 200)
        self.policy_map.remove_fip_ratelimit_cache("ingress", fip)
        self.assertIsNone(self.policy_map.ingress_ratelimits.get(fip))
        self.policy_map.remove_fip_ratelimit_cache("egress", fip)
        self.assertIsNone(self.policy_map.egress_ratelimits.get(fip))

    def test_set_fip_ratelimit_cache(self):
        fip = "1.1.1.1"
        self.policy_map.set_fip_ratelimit_cache(
            "ingress", fip, 100, 200)
        self.policy_map.set_fip_ratelimit_cache(
            "egress", fip, 300, 400)
        in_rate, in_burst = self.policy_map.get_fip_ratelimit_cache(
            "ingress", fip)
        self.assertEqual(100, in_rate)
        self.assertEqual(200, in_burst)
        e_rate, e_burst = self.policy_map.get_fip_ratelimit_cache(
            "egress", fip)
        self.assertEqual(300, e_rate)
        self.assertEqual(400, e_burst)
