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

import mock

from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.agent.linux import tc_lib
from neutron.objects.qos import rule
from neutron.plugins.ml2.drivers.linuxbridge.agent.common import config  # noqa
from neutron.plugins.ml2.drivers.linuxbridge.agent.extension_drivers import (
    qos_driver)
from neutron.tests import base


TEST_LATENCY_VALUE = 100


class QosLinuxbridgeAgentDriverTestCase(base.BaseTestCase):

    def setUp(self):
        super(QosLinuxbridgeAgentDriverTestCase, self).setUp()
        cfg.CONF.set_override("tbf_latency", TEST_LATENCY_VALUE, "QOS")
        self.qos_driver = qos_driver.QosLinuxbridgeAgentDriver()
        self.qos_driver.initialize()
        self.rule = self._create_bw_limit_rule_obj()
        self.port = self._create_fake_port(uuidutils.generate_uuid())

    def _create_bw_limit_rule_obj(self):
        rule_obj = rule.QosBandwidthLimitRule()
        rule_obj.id = uuidutils.generate_uuid()
        rule_obj.max_kbps = 2
        rule_obj.max_burst_kbps = 200
        rule_obj.obj_reset_changes()
        return rule_obj

    def _create_fake_port(self, policy_id):
        return {'qos_policy_id': policy_id,
                'network_qos_policy_id': None,
                'device': 'fake_tap'}

    def test_create_rule(self):
        with mock.patch.object(
            tc_lib.TcCommand, "set_filters_bw_limit"
        ) as set_bw_limit:
            self.qos_driver.create_bandwidth_limit(self.port, self.rule)
            set_bw_limit.assert_called_once_with(
                self.rule.max_kbps, self.rule.max_burst_kbps,
            )

    def test_update_rule(self):
        with mock.patch.object(
            tc_lib.TcCommand, "update_filters_bw_limit"
        ) as update_bw_limit:
            self.qos_driver.update_bandwidth_limit(self.port, self.rule)
            update_bw_limit.assert_called_once_with(
                self.rule.max_kbps, self.rule.max_burst_kbps,
            )

    def test_delete_rule(self):
        with mock.patch.object(
            tc_lib.TcCommand, "delete_filters_bw_limit"
        ) as delete_bw_limit:
            self.qos_driver.delete_bandwidth_limit(self.port)
            delete_bw_limit.assert_called_once_with()
