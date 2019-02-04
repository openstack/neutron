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

import copy

import mock
from neutron_lib import constants as lib_const
from neutron_lib import context
from oslo_utils import uuidutils

from neutron.agent.l3 import agent as l3_agent
from neutron.agent.l3.extensions.qos import gateway_ip as gateway_ip_qos
from neutron.agent.l3 import l3_agent_extension_api as l3_ext_api
from neutron.agent.l3 import router_info as l3router
from neutron.api.rpc.callbacks.consumer import registry
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import resources_rpc
from neutron.objects.qos import policy
from neutron.objects.qos import rule
from neutron.tests.unit.agent.l3 import test_agent

_uuid = uuidutils.generate_uuid

TEST_QOS_GW_IP = "172.24.4.1"

HOSTNAME = 'myhost'


class QosExtensionBaseTestCase(test_agent.BasicRouterOperationsFramework):

    def setUp(self):
        super(QosExtensionBaseTestCase, self).setUp()

        self.gw_ip_qos_ext = gateway_ip_qos.RouterGatewayIPQosAgentExtension()
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
        self.ex_gw_port = {'id': _uuid(),
                           'fixed_ips': [
                               {'ip_address': TEST_QOS_GW_IP}],
                           'qos_policy_id': self.policy.id,
                           'enable_snat': True}
        self.fip = {'id': _uuid(),
                    'floating_ip_address': '172.24.4.9',
                    'fixed_ip_address': '192.168.0.1',
                    'floating_network_id': _uuid(),
                    'port_id': _uuid(),
                    'host': HOSTNAME,
                    'qos_policy_id': self.policy.id}
        self.router = {'id': _uuid(),
                       'gw_port': self.ex_gw_port,
                       'ha': False,
                       'distributed': False,
                       lib_const.FLOATINGIP_KEY: [self.fip],
                       'external_gateway_info': self.ex_gw_port}
        self.router_info = l3router.RouterInfo(self.agent, self.router['id'],
                                               self.router, **self.ri_kwargs)
        self.router_info.ex_gw_port = self.ex_gw_port
        self.agent.router_info[self.router['id']] = self.router_info

        def _mock_get_router_info(router_id):
            return self.router_info

        self.get_router_info = mock.patch(
            'neutron.agent.l3.l3_agent_extension_api.'
            'L3AgentExtensionAPI.get_router_info').start()
        self.get_router_info.side_effect = _mock_get_router_info

        self.agent_api = l3_ext_api.L3AgentExtensionAPI(None)
        self.gw_ip_qos_ext.consume_api(self.agent_api)


class RouterGatewayIPQosAgentExtensionInitializeTestCase(
        QosExtensionBaseTestCase):

    @mock.patch.object(registry, 'register')
    @mock.patch.object(resources_rpc, 'ResourcesPushRpcCallback')
    def test_initialize_subscribed_to_rpc(self, rpc_mock, subscribe_mock):
        call_to_patch = 'neutron_lib.rpc.Connection'
        with mock.patch(call_to_patch,
                        return_value=self.connection) as create_connection:
            self.gw_ip_qos_ext.initialize(
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


class RouterGatewayIPQosAgentExtensionTestCase(
        QosExtensionBaseTestCase):

    def setUp(self):
        super(RouterGatewayIPQosAgentExtensionTestCase, self).setUp()
        self.gw_ip_qos_ext.initialize(
            self.connection, lib_const.L3_AGENT_MODE)
        self._set_pull_mock()

    def _set_pull_mock(self):

        def _pull_mock(context, resource_type, resource_id):
            return self.qos_policies[resource_id]

        self.pull = mock.patch(
            'neutron.api.rpc.handlers.resources_rpc.'
            'ResourcesPullRpcApi.pull').start()
        self.pull.side_effect = _pull_mock

    def _test_gateway_ip_add(self, func):
        tc_wrapper = mock.Mock()
        with mock.patch.object(self.gw_ip_qos_ext, '_get_tc_wrapper',
                               return_value=tc_wrapper):
            func(self.context, self.router)
            tc_wrapper.set_ip_rate_limit.assert_has_calls(
                [mock.call(lib_const.INGRESS_DIRECTION,
                           TEST_QOS_GW_IP, 1111, 2222),
                 mock.call(lib_const.EGRESS_DIRECTION,
                           TEST_QOS_GW_IP, 3333, 4444)],
                any_order=True)

            self.assertEqual(
                {self.router_info.router_id: self.policy.id},
                self.gw_ip_qos_ext.gateway_ip_qos_map.resource_policies)

    def test_add_router(self):
        self._test_gateway_ip_add(self.gw_ip_qos_ext.add_router)

    def test_update_router(self):
        self._test_gateway_ip_add(self.gw_ip_qos_ext.update_router)

    def test__process_update_policy(self):
        tc_wrapper = mock.Mock()
        with mock.patch.object(self.gw_ip_qos_ext, '_get_tc_wrapper',
                               return_value=tc_wrapper):
            self.gw_ip_qos_ext.add_router(self.context, self.router)
            tc_wrapper.set_ip_rate_limit.assert_has_calls(
                [mock.call(lib_const.INGRESS_DIRECTION,
                           TEST_QOS_GW_IP, 1111, 2222),
                 mock.call(lib_const.EGRESS_DIRECTION,
                           TEST_QOS_GW_IP, 3333, 4444)],
                any_order=True)
            new_policy = copy.deepcopy(self.policy)
            new_policy.rules = [self.new_ingress_rule, self.egress_rule]
            self.gw_ip_qos_ext._process_update_policy(new_policy)
            self.assertEqual(
                {self.router_info.router_id: self.policy.id},
                self.gw_ip_qos_ext.gateway_ip_qos_map.resource_policies)
            tc_wrapper.set_ip_rate_limit.assert_has_calls(
                [mock.call(lib_const.INGRESS_DIRECTION,
                           TEST_QOS_GW_IP, 5555, 6666),
                 mock.call(lib_const.EGRESS_DIRECTION,
                           TEST_QOS_GW_IP, 3333, 4444)],
                any_order=True)
