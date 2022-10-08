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
from unittest import mock

from neutron_lib import constants
from neutron_lib import context
from neutron_lib.services.qos import constants as qos_consts
from oslo_utils import uuidutils

from neutron.objects.qos import policy
from neutron.objects.qos import rule
from neutron.plugins.ml2.common import constants as comm_consts
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
            self.qos_driver, '_qos_bandwidth_initialize').start()
        os_ken_app = mock.Mock()
        self.agent_api = ovs_ext_api.OVSAgentExtensionAPI(
                         ovs_bridge.OVSAgentBridge(
                             'br-int', os_ken_app=os_ken_app),
                         ovs_bridge.OVSAgentBridge(
                             'br-tun', os_ken_app=os_ken_app),
                         {'phys1': ovs_bridge.OVSAgentBridge(
                             'br-phys1', os_ken_app=os_ken_app)})
        self.qos_driver.consume_api(self.agent_api)
        mock.patch.object(
            qos_driver.MeterRuleManager, '_init_max_meter_id').start()
        self.qos_driver.initialize()
        self.qos_driver.br_int = mock.Mock()
        self.qos_driver.br_int.get_dp = mock.Mock(return_value=(mock.Mock(),
                                                                mock.Mock(),
                                                                mock.Mock()))
        self.qos_driver.meter_cache_pps.br_int = self.qos_driver.br_int
        self.qos_driver.meter_cache_pps.max_meter = 65535
        self.qos_driver.br_int.list_meter_features = mock.Mock(
            return_value=[{"max_meter": 65535,
                           "band_types": 2,
                           "capabilities": 15,
                           "max_bands": 8}])
        self.qos_driver.br_int.get_egress_bw_limit_for_port = mock.Mock(
            return_value=(1000, 10))
        self.get_egress = self.qos_driver.br_int.get_egress_bw_limit_for_port
        self.qos_driver.br_int.del_egress_bw_limit_for_port = mock.Mock()
        self.delete_egress = (
            self.qos_driver.br_int.delete_egress_bw_limit_for_port)
        self.delete_ingress = (
            self.qos_driver.br_int.delete_ingress_bw_limit_for_port)
        self.create_egress = (
            self.qos_driver.br_int.create_egress_bw_limit_for_port)
        self.update_ingress = (
            self.qos_driver.br_int.update_ingress_bw_limit_for_port)

        self.apply_meter_to_port = (
            self.qos_driver.br_int.apply_meter_to_port)
        self.remove_meter_from_port = (
            self.qos_driver.br_int.remove_meter_from_port)
        self.delete_meter = (
            self.qos_driver.br_int.delete_meter)
        self.create_meter = (
            self.qos_driver.br_int.create_meter)
        self.update_meter = (
            self.qos_driver.br_int.update_meter)

        self.rules = [
            self._create_bw_limit_rule_obj(constants.EGRESS_DIRECTION),
            self._create_bw_limit_rule_obj(constants.INGRESS_DIRECTION),
            self._create_pps_limit_rule_obj(constants.EGRESS_DIRECTION),
            self._create_pps_limit_rule_obj(constants.INGRESS_DIRECTION),
            self._create_dscp_marking_rule_obj()]
        self.qos_policy = self._create_qos_policy_obj(self.rules)
        self.port = self._create_fake_port(self.qos_policy.id)
        self.qos_driver.br_int.get_port_tag_by_name = mock.Mock(
            return_value=1)
        self.addCleanup(self._reset_meter_id_generator_singleton)

    @staticmethod
    def _reset_meter_id_generator_singleton():
        if hasattr(qos_driver.MeterIDGenerator, '_instance'):
            del(qos_driver.MeterIDGenerator._instance)

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

    def _create_pps_limit_rule_obj(self, direction):
        rule_obj = rule.QosPacketRateLimitRule()
        rule_obj.id = uuidutils.generate_uuid()
        rule_obj.max_kpps = 2000
        rule_obj.max_burst_kpps = 200
        rule_obj.direction = direction
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

        port_id = uuidutils.generate_uuid()

        class FakeVifPort(object):
            port_name = self.port_name
            ofport = 111
            vif_id = port_id
            vif_mac = "aa:bb:cc:dd:ee:ff"

        return {'vif_port': FakeVifPort(),
                'qos_policy_id': policy_id,
                'qos_network_policy_id': None,
                'port_id': port_id,
                'device_owner': uuidutils.generate_uuid()}

    def test_create_new_rules(self):
        self.qos_driver.br_int.get_value_from_other_config = mock.Mock()
        self.qos_driver.br_int.set_value_to_other_config = mock.Mock()

        self.qos_driver.br_int.get_egress_bw_limit_for_port = mock.Mock(
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

        self.create_meter.assert_has_calls(
            [mock.call(mock.ANY, self.rules[2].max_kpps * 1000,
             burst=self.rules[2].max_burst_kpps * 1000,
             type_=comm_consts.METER_FLAG_PPS),
             mock.call(mock.ANY, self.rules[3].max_kpps * 1000,
             burst=self.rules[3].max_burst_kpps * 1000,
             type_=comm_consts.METER_FLAG_PPS)])
        self.apply_meter_to_port.assert_has_calls(
            [mock.call(mock.ANY, constants.EGRESS_DIRECTION,
                       "aa:bb:cc:dd:ee:ff",
                       in_port=111,
                       type_=comm_consts.METER_FLAG_PPS),
             mock.call(mock.ANY, constants.INGRESS_DIRECTION,
                       "aa:bb:cc:dd:ee:ff",
                       local_vlan=1,
                       type_=comm_consts.METER_FLAG_PPS)])

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

        self.create_meter.assert_not_called()
        self.apply_meter_to_port.assert_not_called()

    def _test_delete_rules(self, qos_policy):
        self.qos_driver.create(self.port, qos_policy)
        self.qos_driver.delete(self.port, qos_policy)
        self.delete_egress.assert_called_once_with(self.port_name)
        self.delete_ingress.assert_called_once_with(self.port_name)

        self.assertEqual(2, self.delete_meter.call_count)
        self.remove_meter_from_port.assert_has_calls(
            [mock.call(constants.EGRESS_DIRECTION,
                       "aa:bb:cc:dd:ee:ff",
                       in_port=111,
                       type_=comm_consts.METER_FLAG_PPS),
             mock.call(constants.INGRESS_DIRECTION,
                       "aa:bb:cc:dd:ee:ff",
                       local_vlan=1,
                       type_=comm_consts.METER_FLAG_PPS)])

    def _test_delete_rules_no_policy(self):
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
        self.delete_meter.assert_not_called()

        self.delete_meter.assert_not_called()
        self.remove_meter_from_port.assert_not_called()

    def test_meter_manager_allocate_meter_id(self):
        meter_cache_pps = qos_driver.MeterRuleManager(mock.Mock())
        meter_cache_pps.generator.max_meter = 10000
        meter_cache_bps = qos_driver.MeterRuleManager(
            mock.Mock(), type_=comm_consts.METER_FLAG_BPS)
        meter_cache_bps.generator.max_meter = 10000
        meter_cache_pps.allocate_meter_id("1", "ingress")
        meter_cache_pps.allocate_meter_id("1", "egress")
        meter_cache_bps.allocate_meter_id("1", "ingress")
        meter_cache_bps.allocate_meter_id("1", "egress")
        meter_cache_pps.allocate_meter_id("2", "ingress")
        meter_cache_pps.allocate_meter_id("2", "egress")
        meter_cache_bps.allocate_meter_id("2", "ingress")
        meter_cache_bps.allocate_meter_id("2", "egress")
        self.assertEqual(
            meter_cache_pps.generator.PORT_METER_ID,
            meter_cache_bps.generator.PORT_METER_ID)
        pps_keys = meter_cache_pps.generator.PORT_METER_ID.keys()
        bps_keys = meter_cache_bps.generator.PORT_METER_ID.keys()
        self.assertEqual(
            2, len([k for k in pps_keys if k.startswith('pps_1')]))
        self.assertEqual(
            2, len([k for k in bps_keys if k.startswith('bps_1')]))
        self.assertEqual(
            2, len([k for k in pps_keys if k.startswith('pps_2')]))
        self.assertEqual(
            2, len([k for k in bps_keys if k.startswith('bps_2')]))
        self.assertEqual(
            meter_cache_pps.generator.PORT_METER_ID.keys(),
            meter_cache_bps.generator.PORT_METER_ID.keys())
        pps_values = list(meter_cache_pps.generator.PORT_METER_ID.values())
        bps_values = list(meter_cache_bps.generator.PORT_METER_ID.values())
        self.assertEqual(pps_values, bps_values)
        except_keys = ["pps_1_ingress", "pps_1_egress",
                       "bps_1_ingress", "bps_1_egress",
                       "pps_2_ingress", "pps_2_egress",
                       "bps_2_ingress", "bps_2_egress"]
        except_values = []
        for key in except_keys:
            value = meter_cache_bps.generator.PORT_METER_ID.get(key)
            if value:
                except_values.append(value)
        self.assertEqual(8, len(set(except_values)))

    def test_meter_manager_remove_port_meter_id(self):
        meter_cache_pps = qos_driver.MeterRuleManager(mock.Mock())
        meter_cache_pps.generator.max_meter = 10000
        meter_cache_bps = qos_driver.MeterRuleManager(
            mock.Mock(), type_=comm_consts.METER_FLAG_BPS)
        meter_cache_bps.generator.max_meter = 10000
        meter_cache_pps.allocate_meter_id("1", "ingress")
        meter_cache_pps.allocate_meter_id("1", "egress")
        meter_cache_bps.allocate_meter_id("1", "ingress")
        meter_cache_bps.allocate_meter_id("1", "egress")
        meter_cache_pps.allocate_meter_id("2", "ingress")
        meter_cache_pps.allocate_meter_id("2", "egress")
        meter_cache_bps.allocate_meter_id("2", "ingress")
        meter_cache_bps.allocate_meter_id("2", "egress")
        self.assertEqual(
            meter_cache_pps.generator.PORT_METER_ID,
            meter_cache_bps.generator.PORT_METER_ID)

        meter_cache_bps.remove_port_meter_id("2", "ingress")
        meter_cache_pps.remove_port_meter_id("1", "egress")

        self.assertNotIn(
            "pps_1_egress", meter_cache_pps.generator.PORT_METER_ID.keys())
        self.assertNotIn(
            "bps_2_ingress", meter_cache_pps.generator.PORT_METER_ID.keys())

        pps_values = list(meter_cache_pps.generator.PORT_METER_ID.values())
        bps_values = list(meter_cache_bps.generator.PORT_METER_ID.values())
        self.assertEqual(pps_values, bps_values)
        except_keys = ["pps_1_ingress",
                       "bps_1_ingress", "bps_1_egress",
                       "pps_2_ingress", "pps_2_egress",
                       "bps_2_egress"]
        except_values = []
        for key in except_keys:
            value = meter_cache_bps.generator.PORT_METER_ID.get(key)
            if value:
                except_values.append(value)
        self.assertEqual(6, len(set(except_values)))

    def _assert_rules_create_updated(self):
        self.create_egress.assert_called_once_with(
            self.port_name, self.rules[0].max_kbps,
            self.rules[0].max_burst_kbps)
        self.update_ingress.assert_called_once_with(
            self.port_name, self.rules[1].max_kbps,
            self.rules[1].max_burst_kbps)

        self.create_meter.assert_has_calls(
            [mock.call(mock.ANY, self.rules[2].max_kpps * 1000,
             burst=self.rules[2].max_burst_kpps * 1000,
             type_=comm_consts.METER_FLAG_PPS),
             mock.call(mock.ANY, self.rules[3].max_kpps * 1000,
             burst=self.rules[3].max_burst_kpps * 1000,
             type_=comm_consts.METER_FLAG_PPS)])
        self.apply_meter_to_port.assert_has_calls(
            [mock.call(mock.ANY, constants.EGRESS_DIRECTION,
                       "aa:bb:cc:dd:ee:ff",
                       in_port=111,
                       type_=comm_consts.METER_FLAG_PPS),
             mock.call(mock.ANY, constants.INGRESS_DIRECTION,
                       "aa:bb:cc:dd:ee:ff",
                       local_vlan=1,
                       type_=comm_consts.METER_FLAG_PPS)])

    def _assert_dscp_rule_create_updated(self):
        # Assert install_instructions is the last call
        self.assertEqual(
            'install_dscp_marking_rule',
            self.qos_driver.br_int.method_calls[-1][0])

        self.qos_driver.br_int.install_dscp_marking_rule.\
            assert_called_once_with(dscp_mark=mock.ANY, port=mock.ANY)

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
            self.qos_driver.ports['p_id'] = {}
            self.qos_driver.delete_minimum_bandwidth({'port_id': 'p_id'})
            mock_delete_minimum_bandwidth_queue.assert_not_called()

            mock_delete_minimum_bandwidth_queue.reset_mock()
            self.qos_driver.ports['p_id'] = {
                (qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH,
                 constants.EGRESS_DIRECTION): 'rule_port'}
            self.qos_driver.delete_minimum_bandwidth({'port_id': 'p_id'})
            mock_delete_minimum_bandwidth_queue.assert_called_once_with('p_id')

    @mock.patch.object(qos_driver, 'LOG')
    def test_update_minimum_bandwidth_no_vif_port(self, mock_log):
        with mock.patch.object(self.qos_driver.br_int,
                               'update_minimum_bandwidth_queue') \
                as mock_delete_minimum_bandwidth_queue:
            self.qos_driver.update_minimum_bandwidth(
                {'port_id': 'portid'}, mock.ANY)
            mock_delete_minimum_bandwidth_queue.assert_not_called()
            mock_log.debug.assert_called_once_with(
                'update_minimum_bandwidth was received for port %s but '
                'vif_port was not found. It seems that port is already '
                'deleted', 'portid')

    @mock.patch.object(qos_driver, 'LOG')
    def test_update_minimum_bandwidth_no_physical_network(self, mock_log):
        with mock.patch.object(self.qos_driver.br_int,
                               'update_minimum_bandwidth_queue') \
                as mock_delete_minimum_bandwidth_queue:
            port = {'vif_port': mock.ANY, 'port_id': 'portid',
                    'physical_network': None}
            self.qos_driver.update_minimum_bandwidth(port, mock.ANY)
            mock_delete_minimum_bandwidth_queue.assert_not_called()
            mock_log.debug.assert_called_once_with(
                'update_minimum_bandwidth was received for port %s but '
                'has no physical network associated', 'portid')

    def test_update_minimum_bandwidth_no_phy_brs(self):
        vif_port = mock.Mock()
        vif_port.ofport = 'ofport'
        rule = mock.Mock()
        rule.min_kbps = 1500
        port = {'port_id': 'port_id', 'vif_port': vif_port,
                'physical_network': mock.ANY}
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
        port = {'port_id': 'port_id', 'vif_port': vif_port,
                'physical_network': mock.ANY}
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

    # TODO(przszc): Update tests when dataplane enforcement is implemented for
    # minimum packet rate rule
    def test_create_minimum_packet_rate(self):
        try:
            port = {'port_id': 'p_id'}
            rule = mock.MagicMock(id='rule_id')
            self.qos_driver.create_minimum_packet_rate(port, rule)
        except Exception:
            self.fail('create_minimum_packet_rate failed')

    def test_update_minimum_packet_rate(self):
        try:
            port = {'port_id': 'p_id'}
            rule = mock.MagicMock(id='rule_id')
            self.qos_driver.update_minimum_packet_rate(port, rule)
        except Exception:
            self.fail('update_minimum_packet_rate failed')

    def test_delete_minimum_packet_rate(self):
        try:
            port = {'port_id': 'p_id'}
            self.qos_driver.delete_minimum_packet_rate(port)
        except Exception:
            self.fail('delete_minimum_packet_rate failed')

    def test_delete_minimum_packet_rate_ingress(self):
        try:
            port = {'port_id': 'p_id'}
            self.qos_driver.delete_minimum_packet_rate_ingress(port)
        except Exception:
            self.fail('delete_minimum_packet_rate_ingress failed')
