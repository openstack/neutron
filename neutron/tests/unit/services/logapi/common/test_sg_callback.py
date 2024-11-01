# Copyright (c) 2018 Fujitsu Limited
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

from unittest import mock

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources

from neutron.services.logapi.common import sg_callback
from neutron.services.logapi.drivers import base as log_driver_base
from neutron.services.logapi.drivers import manager as driver_mgr
from neutron.tests import base

FAKE_DRIVER = None


class FakeDriver(log_driver_base.DriverBase):

    @staticmethod
    def create():
        return FakeDriver(
            name='fake_driver',
            vif_types=[],
            vnic_types=[],
            supported_logging_types=['security_group'],
            requires_rpc=True
        )


def fake_register():
    global FAKE_DRIVER
    if not FAKE_DRIVER:
        FAKE_DRIVER = FakeDriver.create()
    driver_mgr.register(resources.SECURITY_GROUP_RULE,
                        sg_callback.SecurityGroupRuleCallBack)


class TestSecurityGroupRuleCallback(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.driver_manager = driver_mgr.LoggingServiceDriverManager()

    @mock.patch.object(sg_callback.SecurityGroupRuleCallBack, 'handle_event')
    def test_handle_event(self, mock_sg_cb):
        fake_register()
        self.driver_manager.register_driver(FAKE_DRIVER)

        registry.publish(
            resources.SECURITY_GROUP_RULE, events.AFTER_CREATE, mock.ANY,
            payload=events.DBEventPayload(mock.ANY, states=(mock.ANY,)))
        mock_sg_cb.assert_called_once_with(
            resources.SECURITY_GROUP_RULE, events.AFTER_CREATE, mock.ANY,
            payload=mock.ANY)
        mock_sg_cb.reset_mock()
        registry.publish('fake_resource', events.AFTER_DELETE, mock.ANY,
                         payload=events.DBEventPayload(mock.ANY,
                                                       states=(mock.ANY,)))
        mock_sg_cb.assert_not_called()
