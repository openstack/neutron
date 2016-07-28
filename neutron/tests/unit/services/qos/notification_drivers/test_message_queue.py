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
from oslo_utils import uuidutils

from neutron.api.rpc.callbacks import events
from neutron import context
from neutron.objects.qos import policy as policy_object
from neutron.objects.qos import rule as rule_object
from neutron.services.qos.notification_drivers import message_queue
from neutron.tests.unit.services.qos import base

DB_PLUGIN_KLASS = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'


class TestQosRpcNotificationDriver(base.BaseQosTestCase):

    def setUp(self):
        super(TestQosRpcNotificationDriver, self).setUp()
        rpc_api_cls = mock.patch('neutron.api.rpc.handlers.resources_rpc'
                                 '.ResourcesPushRpcApi').start()
        self.rpc_api = rpc_api_cls.return_value
        self.driver = message_queue.RpcQosServiceNotificationDriver()
        policy_id = uuidutils.generate_uuid()
        self.policy_data = {'policy': {
                            'id': policy_id,
                            'tenant_id': uuidutils.generate_uuid(),
                            'name': 'testi-policy',
                            'description': 'test policyi description',
                            'shared': True}}

        self.rule_data = {'bandwidth_limit_rule': {
                            'id': policy_id,
                            'max_kbps': 100,
                            'max_burst_kbps': 150}}

        self.context = context.get_admin_context()
        self.policy = policy_object.QosPolicy(self.context,
                        **self.policy_data['policy'])

        self.rule = rule_object.QosBandwidthLimitRule(
                                self.context,
                                **self.rule_data['bandwidth_limit_rule'])

    def _validate_push_params(self, event_type, policy):
        self.rpc_api.push.assert_called_once_with(self.context, [policy],
                                                  event_type)

    def test_create_policy(self):
        self.driver.create_policy(self.context, self.policy)
        self.assertFalse(self.rpc_api.push.called)

    def test_update_policy(self):
        self.driver.update_policy(self.context, self.policy)
        self._validate_push_params(events.UPDATED, self.policy)

    def test_delete_policy(self):
        self.driver.delete_policy(self.context, self.policy)
        self._validate_push_params(events.DELETED, self.policy)
