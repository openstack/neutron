# Copyright (c) 2013 OpenStack Foundation
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

import contextlib
import mock

from neutron.services.firewall.agents import firewall_agent_api as api
from neutron.services.firewall.drivers import fwaas_base as base_driver
from neutron.tests import base


class NoopFwaasDriver(base_driver.FwaasDriverBase):
    """Noop Fwaas Driver.

    Firewall driver which does nothing.
    This driver is for disabling Fwaas functionality.
    """

    def create_firewall(self, apply_list, firewall):
        pass

    def delete_firewall(self, apply_list, firewall):
        pass

    def update_firewall(self, apply_list, firewall):
        pass

    def apply_default_policy(self, apply_list, firewall):
        pass


class TestFWaaSAgentApi(base.BaseTestCase):
    def setUp(self):
        super(TestFWaaSAgentApi, self).setUp()

        self.api = api.FWaaSPluginApiMixin(
            'topic',
            'host')

    def test_init(self):
        self.assertEqual(self.api.host, 'host')

    def test_set_firewall_status(self):
        with contextlib.nested(
            mock.patch.object(self.api, 'make_msg'),
            mock.patch.object(self.api, 'call')
        ) as (mock_make_msg, mock_call):

            self.assertEqual(
                self.api.set_firewall_status(
                    mock.sentinel.context,
                    'firewall_id',
                    'status'),
                mock_call.return_value)

            mock_make_msg.assert_called_once_with(
                'set_firewall_status',
                host='host',
                firewall_id='firewall_id',
                status='status')

            mock_call.assert_called_once_with(
                mock.sentinel.context,
                mock_make_msg.return_value)

    def test_firewall_deleted(self):
        with contextlib.nested(
            mock.patch.object(self.api, 'make_msg'),
            mock.patch.object(self.api, 'call')
        ) as (mock_make_msg, mock_call):

            self.assertEqual(
                self.api.firewall_deleted(
                    mock.sentinel.context,
                    'firewall_id'),
                mock_call.return_value)

            mock_make_msg.assert_called_once_with(
                'firewall_deleted',
                host='host',
                firewall_id='firewall_id')

            mock_call.assert_called_once_with(
                mock.sentinel.context,
                mock_make_msg.return_value)
