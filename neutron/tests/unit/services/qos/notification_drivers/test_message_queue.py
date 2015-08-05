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

from neutron.api.rpc.callbacks import events
from neutron.api.rpc.callbacks import resources
from neutron import context
from neutron.objects.qos import policy as policy_object
from neutron.objects.qos import rule as rule_object
from neutron.services.qos.notification_drivers import message_queue
from neutron.tests import base

DB_PLUGIN_KLASS = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'


class TestQosRpcNotificationDriver(base.BaseTestCase):

    def setUp(self):
        super(TestQosRpcNotificationDriver, self).setUp()

        registry_p = mock.patch(
                            'neutron.api.rpc.callbacks.registry.notify')
        self.registry_m = registry_p.start()
        self.driver = message_queue.RpcQosServiceNotificationDriver()

        self.policy_data = {'policy': {
                            'id': 7777777,
                            'tenant_id': 888888,
                            'name': 'testi-policy',
                            'description': 'test policyi description',
                            'shared': True}}

        self.rule_data = {'bandwidth_limit_rule': {
                            'id': 7777777,
                            'max_kbps': 100,
                            'max_burst_kbps': 150}}

        self.policy = policy_object.QosPolicy(context,
                        **self.policy_data['policy'])

        self.rule = rule_object.QosBandwidthLimitRule(
                                context,
                                **self.rule_data['bandwidth_limit_rule'])

    def _validate_registry_params(self, event_type, policy):
        self.assertTrue(self.registry_m.called, policy)
        self.registry_m.assert_called_once_with(
                resources.QOS_POLICY,
                event_type,
                policy)

    def test_create_policy(self):
        self.driver.create_policy(self.policy)
        self.assertFalse(self.registry_m.called)

    def test_update_policy(self):
        self.driver.update_policy(self.policy)
        self._validate_registry_params(events.UPDATED, self.policy)

    def test_delete_policy(self):
        self.driver.delete_policy(self.policy)
        self._validate_registry_params(events.DELETED, self.policy)
