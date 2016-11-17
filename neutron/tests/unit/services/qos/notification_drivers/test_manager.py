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

from neutron.conf.services import qos_driver_manager as driver_mgr_config
from neutron import context
from neutron.objects.qos import policy as policy_object
from neutron.services.qos.notification_drivers import manager as driver_mgr
from neutron.services.qos.notification_drivers import message_queue
from neutron.tests.unit.services.qos import base

DUMMY_DRIVER = ("neutron.tests.unit.services.qos.notification_drivers."
                "dummy.DummyQosServiceNotificationDriver")


def _load_multiple_drivers():
    cfg.CONF.set_override(
        "notification_drivers",
        ["message_queue", DUMMY_DRIVER],
        "qos")


class TestQosDriversManagerBase(base.BaseQosTestCase):

    def setUp(self):
        super(TestQosDriversManagerBase, self).setUp()
        self.config_parse()
        self.setup_coreplugin(load_plugins=False)
        config = cfg.ConfigOpts()
        driver_mgr_config.register_qos_plugin_opts(config)
        self.policy_data = {'policy': {
                            'id': uuidutils.generate_uuid(),
                            'project_id': uuidutils.generate_uuid(),
                            'name': 'test-policy',
                            'description': 'test policy description',
                            'shared': True}}

        self.context = context.get_admin_context()
        self.policy = policy_object.QosPolicy(self.context,
                        **self.policy_data['policy'])
        ctxt = None
        self.kwargs = {'context': ctxt}


class TestQosDriversManagerMulti(TestQosDriversManagerBase):

    def _test_multi_drivers_configuration_op(self, op):
        _load_multiple_drivers()
        driver_manager = driver_mgr.QosServiceNotificationDriverManager()
        handler = '%s_policy' % op
        with mock.patch('.'.join([DUMMY_DRIVER, handler])) as dummy_mock:
            rpc_driver = message_queue.RpcQosServiceNotificationDriver
            with mock.patch.object(rpc_driver, handler) as rpc_mock:
                getattr(driver_manager, handler)(self.context, self.policy)
        for mock_ in (dummy_mock, rpc_mock):
            mock_.assert_called_with(self.context, self.policy)

    def test_multi_drivers_configuration_create(self):
        self._test_multi_drivers_configuration_op('create')

    def test_multi_drivers_configuration_update(self):
        self._test_multi_drivers_configuration_op('update')

    def test_multi_drivers_configuration_delete(self):
        self._test_multi_drivers_configuration_op('delete')
