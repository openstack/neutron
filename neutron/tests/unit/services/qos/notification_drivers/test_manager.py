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

from neutron.api.rpc.callbacks import events
from neutron.api.rpc.callbacks import resources
from neutron import context
from neutron.objects.qos import policy as policy_object
from neutron.services.qos.notification_drivers import manager as driver_mgr
from neutron.services.qos.notification_drivers import message_queue
from neutron.tests import base

DUMMY_DRIVER = ("neutron.tests.unit.services.qos.notification_drivers."
                "dummy.DummyQosServiceNotificationDriver")


def _load_multiple_drivers():
    cfg.CONF.set_override(
        "service_notification_drivers",
        ["message_queue", DUMMY_DRIVER],
        "qos")


class TestQosDriversManager(base.BaseTestCase):

    def setUp(self):
        super(TestQosDriversManager, self).setUp()
        self.config_parse()
        self.setup_coreplugin()
        self.registry_p = mock.patch(
                            'neutron.api.rpc.callbacks.registry.notify')
        self.registry_m = self.registry_p.start()
        self.driver_manager = driver_mgr.QosServiceNotificationDriverManager()
        config = cfg.ConfigOpts()
        config.register_opts(driver_mgr.QOS_PLUGIN_OPTS, "qos")
        self.policy_data = {'policy': {
                            'id': 7777777,
                            'tenant_id': 888888,
                            'name': 'test-policy',
                            'description': 'test policy description',
                            'shared': True}}

        self.policy = policy_object.QosPolicy(context,
                        **self.policy_data['policy'])
        ctxt = None
        self.kwargs = {'context': ctxt}

    def _validate_registry_params(self, event_type, policy):
        self.assertTrue(self.registry_m.called, policy)
        self.registry_m.assert_called_with(
                resources.QOS_POLICY,
                event_type,
                policy)

    def test_create_policy_default_configuration(self):
        #RPC driver should be loaded by default
        self.driver_manager.create_policy(self.policy)
        self.assertFalse(self.registry_m.called)

    def test_update_policy_default_configuration(self):
        #RPC driver should be loaded by default
        self.driver_manager.update_policy(self.policy)
        self._validate_registry_params(events.UPDATED, self.policy)

    def test_delete_policy_default_configuration(self):
        #RPC driver should be loaded by default
        self.driver_manager.delete_policy(self.policy)
        self._validate_registry_params(events.DELETED, self.policy)

    def _test_multi_drivers_configuration_op(self, op):
        _load_multiple_drivers()
        # create a new manager with new configuration
        driver_manager = driver_mgr.QosServiceNotificationDriverManager()
        handler = '%s_policy' % op
        with mock.patch('.'.join([DUMMY_DRIVER, handler])) as dummy_mock:
            rpc_driver = message_queue.RpcQosServiceNotificationDriver
            with mock.patch.object(rpc_driver, handler) as rpc_mock:
                getattr(driver_manager, handler)(self.policy)
        for mock_ in (dummy_mock, rpc_mock):
            mock_.assert_called_with(self.policy)

    def test_multi_drivers_configuration_create(self):
        self._test_multi_drivers_configuration_op('create')

    def test_multi_drivers_configuration_update(self):
        self._test_multi_drivers_configuration_op('update')

    def test_multi_drivers_configuration_delete(self):
        self._test_multi_drivers_configuration_op('delete')
