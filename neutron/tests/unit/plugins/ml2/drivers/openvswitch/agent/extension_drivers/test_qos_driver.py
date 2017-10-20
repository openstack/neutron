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
from neutron_lib import constants
from neutron_lib import context
from oslo_utils import uuidutils

from neutron.objects.qos import policy
from neutron.objects.qos import rule
from neutron.plugins.ml2.drivers.openvswitch.agent import (
        ovs_agent_extension_api as ovs_ext_api)
from neutron.plugins.ml2.drivers.openvswitch.agent.extension_drivers import (
    qos_driver)
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.native import (
    ovs_bridge)
from neutron.tests.unit.plugins.ml2.drivers.openvswitch.agent import (
    ovs_test_base)


class QosOVSAgentDriverTestCase(ovs_test_base.OVSAgentConfigTestBase):

    def setUp(self):
        super(QosOVSAgentDriverTestCase, self).setUp()
        conn_patcher = mock.patch(
            'neutron.agent.ovsdb.impl_idl._connection')
        conn_patcher.start()
        self.addCleanup(conn_patcher.stop)
        self.context = context.get_admin_context()
        self.qos_driver = qos_driver.QosOVSAgentDriver()
        self.mock_clear_minimum_bandwidth_qos = mock.patch.object(
            self.qos_driver, '_minimum_bandwidth_initialize').start()
        os_ken_app = mock.Mock()
        self.agent_api = ovs_ext_api.OVSAgentExtensionAPI(
                         ovs_bridge.OVSAgentBridge(
                             'br-int', os_ken_app=os_ken_app),
                         ovs_bridge.OVSAgentBridge(
                             'br-tun', os_ken_app=os_ken_app),
                         {'phys1': ovs_bridge.OVSAgentBridge(
                             'br-phys1', os_ken_app=os_ken_app)})
        self.qos_driver.consume_api(self.agent_api)
        self.qos_driver.initialize()
        self.qos_driver.br_int = mock.Mock()
        self.qos_driver.br_int.get_egress_bw_limit_for_port = mock.Mock(
            return_value=(1000, 10))
        self.get_egress = self.qos_driver.br_int.get_egress_bw_limit_for_port
        self.get_ingress = self.qos_driver.br_int.get_ingress_bw_limit_for_port
        self.qos_driver.br_int.dump_flows_for = mock.Mock(return_value=None)
        self.qos_driver.br_int.del_egress_bw_limit_for_port = mock.Mock()
        self.delete_egress = (
            self.qos_driver.br_int.delete_egress_bw_limit_for_port)
        self.delete_ingress = (
            self.qos_driver.br_int.delete_ingress_bw_limit_for_port)
        self.create_egress = (
            self.qos_driver.br_int.create_egress_bw_limit_for_port)
        self.update_ingress = (
            self.qos_driver.br_int.update_ingress_bw_limit_for_port)
        self.rules = [
            self._create_bw_limit_rule_obj(constants.EGRESS_DIRECTION),
            self._create_bw_limit_rule_obj(constants.INGRESS_DIRECTION),
            self._create_dscp_marking_rule_obj()]
        self.qos_policy = self._create_qos_policy_obj(self.rules)
        self.port = self._create_fake_port(self.qos_policy.id)

    def _create_bw_limit_rule_obj(self, direction):
        rule_obj = rule.QosBandwidthLimitRule()
        rule_obj.id = uuidutils.generate_uuid()
        rule_obj.max_kbps = 2
        rule_obj.max_burst_kbps = 200
        rule_obj.direction = direction
        rule_obj.obj_reset_changes()
        return rule_obj

    def _create_dscp_marking_rule_obj(self):
        rule_obj = rule.QosDscpMarkingRule()
        rule_obj.id = uuidutils.generate_uuid()
        rule_obj.dscp_mark = 32
        rule_obj.obj_reset_changes()
        return rule_obj

    def _create_qos_policy_obj(self, rules):
        policy_dict = {'id': uuidutils.generate_uuid(),
                'project_id': uuidutils.generate_uuid(),
                'name': 'test',
                'description': 'test',
                'shared': False,
                'rules': rules}
        policy_obj = policy.QosPolicy(self.context, **policy_dict)
        policy_obj.obj_reset_changes()
        for policy_rule in policy_obj.rules:
            policy_rule.qos_policy_id = policy_obj.id
            policy_rule.obj_reset_changes()
        return policy_obj

    def _create_fake_port(self, policy_id):
        self.port_name = 'fakeport'

        class FakeVifPort(object):
            port_name = self.port_name
            ofport = 111

        return {'vif_port': FakeVifPort(),
                'qos_policy_id': policy_id,
                'network_qos_policy_id': None,
                'port_id': uuidutils.generate_uuid(),
                'device_owner': uuidutils.generate_uuid()}

    def test_create_new_rules(self):
        self.qos_driver.br_int.get_egress_bw_limit_for_port = mock.Mock(
            return_value=(None, None))
        self.qos_driver.br_int.get_ingress_bw_limit_for_port = mock.Mock(
            return_value=(None, None))
        self.qos_driver.create(self.port, self.qos_policy)
        self.assertEqual(0, self.delete_egress.call_count)
        self.assertEqual(0, self.delete_ingress.call_count)
        self.create_egress.assert_called_once_with(
            self.port_name, self.rules[0].max_kbps,
            self.rules[0].max_burst_kbps)
        self.update_ingress.assert_called_once_with(
            self.port_name, self.rules[1].max_kbps,
            self.rules[1].max_burst_kbps)
        self._assert_dscp_rule_create_updated()

    def test_create_existing_rules(self):
        self.qos_driver.create(self.port, self.qos_policy)
        self._assert_rules_create_updated()
        self._assert_dscp_rule_create_updated()

    def test_update_rules(self):
        self.qos_driver.update(self.port, self.qos_policy)
        self._assert_rules_create_updated()
        self._assert_dscp_rule_create_updated()

    def test_update_rules_no_vif_port(self):
        port = copy.copy(self.port)
        port.pop("vif_port")
        self.qos_driver.update(port, self.qos_policy)
        self.create_egress.assert_not_called()
        self.update_ingress.assert_not_called()

    def _test_delete_rules(self, qos_policy):
        self.qos_driver.br_int.get_ingress_bw_limit_for_port = mock.Mock(
            return_value=(self.rules[1].max_kbps,
                          self.rules[1].max_burst_kbps))
        self.qos_driver.create(self.port, qos_policy)
        self.qos_driver.delete(self.port, qos_policy)
        self.delete_egress.assert_called_once_with(self.port_name)
        self.delete_ingress.assert_called_once_with(self.port_name)

    def _test_delete_rules_no_policy(self):
        self.qos_driver.br_int.get_ingress_bw_limit_for_port = mock.Mock(
            return_value=(self.rules[1].max_kbps,
                          self.rules[1].max_burst_kbps))
        self.qos_driver.delete(self.port)
        self.delete_egress.assert_called_once_with(self.port_name)
        self.delete_ingress.assert_called_once_with(self.port_name)

    def test_delete_rules(self):
        self._test_delete_rules(self.qos_policy)

    def test_delete_rules_no_policy(self):
        self._test_delete_rules_no_policy()

    def test_delete_rules_no_vif_port(self):
        port = copy.copy(self.port)
        port.pop("vif_port")
        self.qos_driver.delete(port, self.qos_policy)
        self.delete_egress.assert_not_called()
        self.delete_ingress.assert_not_called()

    def _assert_rules_create_updated(self):
        self.create_egress.assert_called_once_with(
            self.port_name, self.rules[0].max_kbps,
            self.rules[0].max_burst_kbps)
        self.update_ingress.assert_called_once_with(
            self.port_name, self.rules[1].max_kbps,
            self.rules[1].max_burst_kbps)

    def _assert_dscp_rule_create_updated(self):
        # Assert add_flow is the last call
        self.assertEqual(
            'add_flow',
            self.qos_driver.br_int.method_calls[-1][0])

        self.qos_driver.br_int.add_flow.assert_called_once_with(
            actions='mod_nw_tos:128,load:55->NXM_NX_REG2[0..5],resubmit(,0)',
            in_port=mock.ANY, priority=65535, reg2=0, table=0)

    def test_create_minimum_bandwidth(self):
        with mock.patch.object(self.qos_driver, 'update_minimum_bandwidth') \
                as mock_update_minimum_bandwidth:
            self.qos_driver.create_minimum_bandwidth('port_name', 'rule')
            mock_update_minimum_bandwidth.assert_called_once_with('port_name',
                                                                  'rule')

    def test_delete_minimum_bandwidth(self):
        with mock.patch.object(self.qos_driver.br_int,
                               'delete_minimum_bandwidth_queue') \
                as mock_delete_minimum_bandwidth_queue:
            self.qos_driver.delete_minimum_bandwidth({'port_id': 'port_id'})
            mock_delete_minimum_bandwidth_queue.assert_called_once_with(
                'port_id')

    def test_update_minimum_bandwidth_no_vif_port(self):
        with mock.patch.object(self.qos_driver.br_int,
                               'update_minimum_bandwidth_queue') \
                as mock_delete_minimum_bandwidth_queue:
            self.qos_driver.update_minimum_bandwidth({}, mock.ANY)
            mock_delete_minimum_bandwidth_queue.assert_not_called()

    def test_update_minimum_bandwidth_no_phy_brs(self):
        vif_port = mock.Mock()
        vif_port.ofport = 'ofport'
        rule = mock.Mock()
        rule.min_kbps = 1500
        port = {'port_id': 'port_id', 'vif_port': vif_port}
        with mock.patch.object(self.qos_driver.br_int,
                               'update_minimum_bandwidth_queue') \
                as mock_delete_minimum_bandwidth_queue, \
                mock.patch.object(self.qos_driver.agent_api,
                                  'request_phy_brs'):
            self.qos_driver.update_minimum_bandwidth(port, rule)
            mock_delete_minimum_bandwidth_queue.assert_called_once_with(
                'port_id', [], 'ofport', 1500)

    def test_update_minimum_bandwidth(self):
        vif_port = mock.Mock()
        vif_port.ofport = 'ofport'
        rule = mock.Mock()
        rule.min_kbps = 1500
        port = {'port_id': 'port_id', 'vif_port': vif_port}
        with mock.patch.object(self.qos_driver.br_int,
                               'update_minimum_bandwidth_queue') \
                as mock_delete_minimum_bandwidth_queue, \
                mock.patch.object(self.qos_driver.agent_api,
                                  'request_phy_brs') as mock_request_phy_brs:
            phy_br = mock.Mock()
            phy_br.get_bridge_ports.return_value = ['port1', 'port2']
            mock_request_phy_brs.return_value = [phy_br]
            self.qos_driver.update_minimum_bandwidth(port, rule)
            mock_delete_minimum_bandwidth_queue.assert_called_once_with(
                'port_id', ['port1', 'port2'], 'ofport', 1500)
