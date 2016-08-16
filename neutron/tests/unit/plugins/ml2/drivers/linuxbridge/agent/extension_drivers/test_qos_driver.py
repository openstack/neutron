# Copyright 2016 OVH SAS
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

import collections
import mock
import uuid

from oslo_utils import uuidutils

from neutron.agent.l2.extensions import qos_linux as qos_extensions
from neutron.agent.linux import tc_lib
from neutron.objects.qos import rule
from neutron.plugins.ml2.drivers.linuxbridge.agent.extension_drivers import (
    qos_driver)
from neutron.services.qos import qos_consts
from neutron.tests import base


DSCP_VALUE = 32


class FakeVifPort(object):
    ofport = 99
    port_name = 'name'
    vif_mac = 'aa:bb:cc:11:22:33'


class QosLinuxbridgeAgentDriverTestCase(base.BaseTestCase):
    POLICY_ID = uuid.uuid4().hex
    DEVICE_NAME = 'fake_tap'
    ACTION_CREATE = 'create'
    ACTION_DELETE = 'delete'
    RULE_MAX = 4000
    RULE_MIN = 1000
    RULE_BURST = 800
    RULE_DIRECTION_EGRESS = 'egress'

    def setUp(self):
        super(QosLinuxbridgeAgentDriverTestCase, self).setUp()
        self.qos_driver = qos_driver.QosLinuxbridgeAgentDriver()
        self.qos_driver.initialize()
        self.rule_bw_limit = self._create_bw_limit_rule_obj()
        self.rule_dscp_marking = self._create_dscp_marking_rule_obj()
        self.get_egress_burst_value = mock.patch.object(
            qos_extensions.QosLinuxAgentDriver, "_get_egress_burst_value")
        self.mock_get_egress_burst_value = self.get_egress_burst_value.start()
        self.mock_get_egress_burst_value.return_value = self.RULE_BURST
        self.rule_bw_limit = self._create_bw_limit_rule_obj()
        self.rule_min_bw = self._create_min_bw_rule_obj()
        self.port = self._create_fake_port(uuidutils.generate_uuid())
        self._ports = collections.defaultdict(dict)

    def _create_bw_limit_rule_obj(self):
        rule_obj = rule.QosBandwidthLimitRule()
        rule_obj.id = uuidutils.generate_uuid()
        rule_obj.max_kbps = self.RULE_MAX
        rule_obj.max_burst_kbps = self.RULE_BURST
        rule_obj.obj_reset_changes()
        return rule_obj

    def _create_min_bw_rule_obj(self):
        rule_obj = rule.QosMinimumBandwidthRule()
        rule_obj.id = uuidutils.generate_uuid()
        rule_obj.min_kbps = self.RULE_MAX
        rule_obj.direction = self.RULE_DIRECTION_EGRESS
        rule_obj.obj_reset_changes()
        return rule_obj

    def _create_dscp_marking_rule_obj(self):
        rule_obj = rule.QosDscpMarkingRule()
        rule_obj.id = uuidutils.generate_uuid()
        rule_obj.dscp_mark = DSCP_VALUE
        rule_obj.obj_reset_changes()
        return rule_obj

    def _create_fake_port(self, policy_id):
        return {'qos_policy_id': policy_id,
                'network_qos_policy_id': None,
                'device': self.DEVICE_NAME,
                'port_id': uuid.uuid4(),
                'vif_port': FakeVifPort()}

    def _dscp_mark_chain_name(self, device):
        return "qos-o%s" % device[3:]

    def _dscp_postrouting_rule(self, device):
        return ("-m physdev --physdev-in %s --physdev-is-bridged "
                "-j $qos-o%s") % (device, device[3:])

    def _dscp_rule(self, dscp_mark_value):
        return "-j DSCP --set-dscp %s" % dscp_mark_value

    def _dscp_rule_tag(self, device):
        return "dscp-%s" % device

    @mock.patch.object(tc_lib.TcCommand, "set_bw")
    def test_update_bandwidth_limit(self, mock_set_bw):
        with mock.patch.object(self.qos_driver, '_get_port_bw_parameters') as \
                mock_bw_param:
            mock_bw_param.return_value = (self.rule_bw_limit.max_kbps,
                                          self.rule_bw_limit.max_burst_kbps,
                                          None)
            self.qos_driver.update_bandwidth_limit(self.port,
                                                   self.rule_bw_limit)
            mock_set_bw.assert_called_once_with(
                self.rule_bw_limit.max_kbps, self.rule_bw_limit.max_burst_kbps,
                None, self.RULE_DIRECTION_EGRESS)
            mock_bw_param.assert_called_once_with(self.port['port_id'])

    @mock.patch.object(tc_lib.TcCommand, "delete_bw")
    def test_delete_bandwidth_limit(self, mock_delete_bw):
        with mock.patch.object(self.qos_driver, '_get_port_bw_parameters') as \
                mock_bw_param:
            mock_bw_param.return_value = (None, None, None)
            self.qos_driver.delete_bandwidth_limit(self.port)
            mock_delete_bw.assert_called_once_with(self.RULE_DIRECTION_EGRESS)
            mock_bw_param.assert_called_once_with(self.port['port_id'])

    @mock.patch.object(tc_lib.TcCommand, "set_bw")
    def test_update_minimum_bandwidth(self, mock_set_bw):
        with mock.patch.object(self.qos_driver, '_get_port_bw_parameters') as \
                mock_bw_param:
            mock_bw_param.return_value = (None, None,
                                          self.rule_min_bw.min_kbps)
            self.qos_driver.update_minimum_bandwidth(self.port,
                                                     self.rule_min_bw)
            mock_set_bw.assert_called_once_with(None, None,
                self.rule_min_bw.min_kbps, self.RULE_DIRECTION_EGRESS)
            mock_bw_param.assert_called_once_with(self.port['port_id'])

    @mock.patch.object(tc_lib.TcCommand, "delete_bw")
    def test_delete_minimum_bandwidth(self, mock_delete_bw):
        with mock.patch.object(self.qos_driver, '_get_port_bw_parameters') as \
                mock_bw_param:
            mock_bw_param.return_value = (None, None, None)
            self.qos_driver.delete_minimum_bandwidth(self.port)
            mock_delete_bw.assert_called_once_with(self.RULE_DIRECTION_EGRESS)
            mock_bw_param.assert_called_once_with(self.port['port_id'])

    def test_create_dscp_marking(self):
        expected_calls = [
            mock.call.add_chain(
                self._dscp_mark_chain_name(self.port['device'])),
            mock.call.add_rule(
                "POSTROUTING",
                self._dscp_postrouting_rule(self.port['device'])),
            mock.call.add_rule(
                self._dscp_mark_chain_name(self.port['device']),
                self._dscp_rule(DSCP_VALUE),
                tag=self._dscp_rule_tag(self.port['device'])
            )
        ]
        with mock.patch.object(
            self.qos_driver, "iptables_manager") as iptables_manager:

            iptables_manager.ip4['mangle'] = mock.Mock()
            iptables_manager.ip6['mangle'] = mock.Mock()
            self.qos_driver.create_dscp_marking(
                self.port, self.rule_dscp_marking)
            iptables_manager.ipv4['mangle'].assert_has_calls(expected_calls)
            iptables_manager.ipv6['mangle'].assert_has_calls(expected_calls)

    def test_update_dscp_marking(self):
        expected_calls = [
            mock.call.clear_rules_by_tag(
                self._dscp_rule_tag(self.port['device'])),
            mock.call.add_chain(
                self._dscp_mark_chain_name(self.port['device'])),
            mock.call.add_rule(
                "POSTROUTING",
                self._dscp_postrouting_rule(self.port['device'])),
            mock.call.add_rule(
                self._dscp_mark_chain_name(self.port['device']),
                self._dscp_rule(DSCP_VALUE),
                tag=self._dscp_rule_tag(self.port['device'])
            )
        ]
        with mock.patch.object(
            self.qos_driver, "iptables_manager") as iptables_manager:

            iptables_manager.ip4['mangle'] = mock.Mock()
            iptables_manager.ip6['mangle'] = mock.Mock()
            self.qos_driver.update_dscp_marking(
                self.port, self.rule_dscp_marking)
            iptables_manager.ipv4['mangle'].assert_has_calls(expected_calls)
            iptables_manager.ipv6['mangle'].assert_has_calls(expected_calls)

    def test_delete_dscp_marking_chain_empty(self):
        dscp_chain_name = self._dscp_mark_chain_name(self.port['device'])
        expected_calls = [
            mock.call.clear_rules_by_tag(
                self._dscp_rule_tag(self.port['device'])),
            mock.call.remove_chain(
                dscp_chain_name),
            mock.call.remove_rule(
                "POSTROUTING",
                self._dscp_postrouting_rule(self.port['device']))
        ]
        with mock.patch.object(
            self.qos_driver, "iptables_manager") as iptables_manager:

            iptables_manager.ip4['mangle'] = mock.Mock()
            iptables_manager.ip6['mangle'] = mock.Mock()
            iptables_manager.get_chain = mock.Mock(return_value=[])
            self.qos_driver.delete_dscp_marking(self.port)
            iptables_manager.ipv4['mangle'].assert_has_calls(expected_calls)
            iptables_manager.ipv6['mangle'].assert_has_calls(expected_calls)
            iptables_manager.get_chain.assert_has_calls([
                mock.call("mangle", dscp_chain_name, ip_version=4),
                mock.call("mangle", dscp_chain_name, ip_version=6)
            ])

    def test_delete_dscp_marking_chain_not_empty(self):
        dscp_chain_name = self._dscp_mark_chain_name(self.port['device'])
        expected_calls = [
            mock.call.clear_rules_by_tag(
                self._dscp_rule_tag(self.port['device'])),
        ]
        with mock.patch.object(
            self.qos_driver, "iptables_manager") as iptables_manager:

            iptables_manager.ip4['mangle'] = mock.Mock()
            iptables_manager.ip6['mangle'] = mock.Mock()
            iptables_manager.get_chain = mock.Mock(
                return_value=["some other rule"])
            self.qos_driver.delete_dscp_marking(self.port)
            iptables_manager.ipv4['mangle'].assert_has_calls(expected_calls)
            iptables_manager.ipv6['mangle'].assert_has_calls(expected_calls)
            iptables_manager.get_chain.assert_has_calls([
                mock.call("mangle", dscp_chain_name, ip_version=4),
                mock.call("mangle", dscp_chain_name, ip_version=6)
            ])
            iptables_manager.ipv4['mangle'].remove_chain.assert_not_called()
            iptables_manager.ipv4['mangle'].remove_rule.assert_not_called()

    def test_get_port_bw_parameters_existing_port(self):
        port_id = 'port_id_1'
        self.qos_driver._port_rules[port_id][
            qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH] = self.rule_min_bw
        self.qos_driver._port_rules[port_id][
            qos_consts.RULE_TYPE_BANDWIDTH_LIMIT] = self.rule_bw_limit
        max, burst, min = self.qos_driver._get_port_bw_parameters(port_id)
        self.assertEqual(self.rule_bw_limit.max_kbps, max)
        self.assertEqual(self.rule_bw_limit.max_burst_kbps, burst)
        self.assertEqual(self.rule_min_bw.min_kbps, min)
        self.mock_get_egress_burst_value.assert_called_once_with(
            self.rule_bw_limit)

    def test_get_port_bw_parameters_not_existing_port(self):
        port_id = 'port_id_1'
        max, burst, min = self.qos_driver._get_port_bw_parameters(port_id)
        self.assertIsNone(max)
        self.assertIsNone(burst)
        self.assertIsNone(min)
