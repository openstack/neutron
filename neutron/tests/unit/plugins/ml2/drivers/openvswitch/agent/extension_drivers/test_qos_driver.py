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

from neutron.extensions import qos
from neutron.plugins.ml2.drivers.openvswitch.agent.extension_drivers import (
    qos_driver)
from neutron.tests.unit.plugins.ml2.drivers.openvswitch.agent import (
    ovs_test_base)


class OVSQoSAgentDriverBwLimitRule(ovs_test_base.OVSAgentConfigTestBase):

    def setUp(self):
        super(OVSQoSAgentDriverBwLimitRule, self).setUp()
        self.qos_driver = qos_driver.QosOVSAgentDriver()
        self.qos_driver.initialize()
        self.qos_driver.br_int = mock.Mock()
        self.qos_driver.br_int.get_qos_bw_limit_for_port = mock.Mock(
            return_value=(1000, 10))
        self.get = self.qos_driver.br_int.get_qos_bw_limit_for_port
        self.qos_driver.br_int.del_qos_bw_limit_for_port = mock.Mock()
        self.delete = self.qos_driver.br_int.del_qos_bw_limit_for_port
        self.qos_driver.br_int.create_qos_bw_limit_for_port = mock.Mock()
        self.create = self.qos_driver.br_int.create_qos_bw_limit_for_port
        self.rule = self._create_bw_limit_rule()
        self.port = self._create_fake_port()

    def _create_bw_limit_rule(self):
        return {'type': qos.RULE_TYPE_BANDWIDTH_LIMIT,
                'max_kbps': '200',
                'max_burst_kbps': '2'}

    def _create_fake_port(self):
        return {'name': 'fakeport'}

    def test_create_new_rule(self):
        self.qos_driver.br_int.get_qos_bw_limit_for_port = mock.Mock(
            return_value=(None, None))
        self.qos_driver.create(self.port, [self.rule])
        # Assert create is the last call
        self.assertEqual(
            'create_qos_bw_limit_for_port',
            self.qos_driver.br_int.method_calls[-1][0])
        self.assertEqual(0, self.delete.call_count)
        self.create.assert_called_once_with(
            self.port['name'], self.rule['max_kbps'],
            self.rule['max_burst_kbps'])

    def test_create_existing_rules(self):
        self.qos_driver.create(self.port, [self.rule])
        self._assert_rule_create_updated()

    def test_update_rules(self):
        self.qos_driver.update(self.port, [self.rule])
        self._assert_rule_create_updated()

    def test_delete_rules(self):
        self.qos_driver.delete(self.port, [self.rule])
        self.delete.assert_called_once_with(self.port['name'])

    def test_unknown_rule_id(self):
        self.rule['type'] = 'unknown'
        self.qos_driver.create(self.port, [self.rule])
        self.assertEqual(0, self.create.call_count)
        self.assertEqual(0, self.delete.call_count)

    def _assert_rule_create_updated(self):
        # Assert create is the last call
        self.assertEqual(
            'create_qos_bw_limit_for_port',
            self.qos_driver.br_int.method_calls[-1][0])

        self.delete.assert_called_once_with(self.port['name'])

        self.create.assert_called_once_with(
            self.port['name'], self.rule['max_kbps'],
            self.rule['max_burst_kbps'])
