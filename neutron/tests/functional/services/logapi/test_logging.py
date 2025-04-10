# Copyright (c) 2017 Fujitsu Limited
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

import re
from unittest import mock

from neutron_lib import constants
from neutron_lib import context as neutron_context
from neutron_lib.plugins.ml2 import ovs_constants as ovs_consts
from oslo_config import cfg
from oslo_log import log as logging
import testscenarios

from neutron.objects.logapi import logging_resource as log_object
from neutron.plugins.ml2.drivers.openvswitch.agent import (
    ovs_agent_extension_api as ovs_ext_api)
from neutron.services.logapi.drivers.openvswitch import (
    ovs_firewall_log as ovs_fw_log)
from neutron.tests.functional.agent import test_firewall

LOG = logging.getLogger(__name__)

load_tests = testscenarios.load_tests_apply_scenarios

FAKE_LOG_ID = 'a2d72369-4246-4f19-bd3c-af51ec8d70cd'
FAKE_PROJECT_ID = 'fake_project'

log_object_dict = {
    'id': FAKE_LOG_ID,
    'resource_type': 'security_group',
    'project_id': FAKE_PROJECT_ID,
    'event': 'ALL'
}
FAKE_LOG_OBJECT = log_object.Log(**log_object_dict)


class LoggingExtensionTestFramework(test_firewall.BaseFirewallTestCase):

    def setUp(self):
        super().setUp()
        cfg.CONF.set_override('extensions', ['log'], group='agent')
        self.context = neutron_context.get_admin_context_without_session()
        self._set_resource_rpc_mock()
        if self.firewall_name != 'openvswitch':
            self.skipTest("Logging extension doesn't support firewall driver"
                          " %s at that time " % self.firewall_name)
        self.log_driver = self.initialize_ovs_fw_log()

    def initialize_ovs_fw_log(self):
        self.int_br = ovs_ext_api.OVSCookieBridge(
            self.of_helper.br_int_cls(self.tester.bridge.br_name))
        self.tun_br = self.of_helper.br_tun_cls('br-tun')
        agent_api = ovs_ext_api.OVSAgentExtensionAPI(
            self.int_br, self.tun_br,
            {'physnet1': self.of_helper.br_phys_cls('br-physnet1')})
        log_driver = ovs_fw_log.OVSFirewallLoggingDriver(agent_api)
        log_driver.initialize(self.resource_rpc)
        return log_driver

    def _set_resource_rpc_mock(self):
        self.log_info = []

        def _get_sg_info_mock(context, **kwargs):
            return self.log_info

        self.resource_rpc = mock.patch(
            'neutron.services.logapi.rpc.agent.LoggingApiStub').start()
        self.resource_rpc.get_sg_log_info_for_log_resources.side_effect = (
            _get_sg_info_mock)

    def _set_ports_log(self, sg_rules):
        fake_sg_log_info = [
            {
                'id': FAKE_LOG_ID,
                'ports_log': [
                    {'port_id': self.src_port_desc['device'],
                     'security_group_rules': sg_rules}],
                'event': 'ALL',
                'project_id': FAKE_PROJECT_ID
            }]
        self.log_info = fake_sg_log_info


class TestLoggingExtension(LoggingExtensionTestFramework):

    ip_cidr = '192.168.0.1/24'

    def _is_log_flow_set(self, table, actions):
        flows = self.log_driver.int_br.br.dump_flows_for_table(table)
        pattern = re.compile(
            fr"^.* table={table}.* actions={actions}"
        )
        for flow in flows.splitlines():
            if pattern.match(flow.strip()):
                return True
        return False

    def _assert_logging_flows_set(self):
        self.assertTrue(self._is_log_flow_set(
            table=ovs_consts.ACCEPTED_EGRESS_TRAFFIC_TABLE,
            actions=r"resubmit\(,%d\),CONTROLLER:65535" % (
                ovs_consts.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE)))
        self.assertTrue(self._is_log_flow_set(
            table=ovs_consts.ACCEPTED_INGRESS_TRAFFIC_TABLE,
            actions="CONTROLLER:65535"))
        self.assertTrue(self._is_log_flow_set(
            table=ovs_consts.DROPPED_TRAFFIC_TABLE,
            actions="CONTROLLER:65535"))

    def _assert_logging_flows_not_set(self):
        self.assertFalse(self._is_log_flow_set(
            table=ovs_consts.ACCEPTED_EGRESS_TRAFFIC_TABLE,
            actions=r"resubmit\(,%d\),CONTROLLER:65535" % (
                ovs_consts.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE)))
        self.assertFalse(self._is_log_flow_set(
            table=ovs_consts.ACCEPTED_INGRESS_TRAFFIC_TABLE,
            actions="CONTROLLER:65535"))
        self.assertFalse(self._is_log_flow_set(
            table=ovs_consts.DROPPED_TRAFFIC_TABLE,
            actions="CONTROLLER:65535"))

    def test_log_lifecycle(self):
        sg_rules = [{'ethertype': constants.IPv4,
                     'direction': constants.INGRESS_DIRECTION,
                     'protocol': constants.PROTO_NAME_ICMP,
                     'security_group_id': self.FAKE_SECURITY_GROUP_ID},
                    {'ethertype': constants.IPv4,
                     'direction': constants.EGRESS_DIRECTION,
                     'security_group_id': self.FAKE_SECURITY_GROUP_ID},
                    {'ethertype': constants.IPv6,
                     'protocol': constants.PROTO_NAME_TCP,
                     'port_range_min': 22,
                     'port_range_max': 22,
                     'remote_group_id': 2,
                     'direction': constants.EGRESS_DIRECTION,
                     'security_group_id': self.FAKE_SECURITY_GROUP_ID},
                    ]
        self.firewall.update_security_group_rules(
            self.FAKE_SECURITY_GROUP_ID, sg_rules)
        self.firewall.update_port_filter(self.src_port_desc)
        self._set_ports_log(sg_rules)

        # start log
        self.log_driver.start_logging(
            self.context, log_resources=[FAKE_LOG_OBJECT])
        self._assert_logging_flows_set()

        # stop log
        self.log_driver.stop_logging(
            self.context, log_resources=[FAKE_LOG_OBJECT])
        self._assert_logging_flows_not_set()
