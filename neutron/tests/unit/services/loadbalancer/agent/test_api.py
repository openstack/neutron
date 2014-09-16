# Copyright 2013 New Dream Network, LLC (DreamHost)
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

from neutron.services.loadbalancer.agent import agent_api as api
from neutron.tests import base


class TestApiCache(base.BaseTestCase):
    def setUp(self):
        super(TestApiCache, self).setUp()

        self.api = api.LbaasAgentApi('topic', mock.sentinel.context, 'host')
        self.make_msg = mock.patch.object(self.api, 'make_msg').start()
        self.mock_call = mock.patch.object(self.api, 'call').start()

    def test_init(self):
        self.assertEqual(self.api.host, 'host')
        self.assertEqual(self.api.context, mock.sentinel.context)

    def test_get_ready_devices(self):
        self.assertEqual(
            self.api.get_ready_devices(),
            self.mock_call.return_value
        )

        self.make_msg.assert_called_once_with('get_ready_devices', host='host')
        self.mock_call.assert_called_once_with(
            mock.sentinel.context,
            self.make_msg.return_value
        )

    def test_get_logical_device(self):
        self.assertEqual(
            self.api.get_logical_device('pool_id'),
            self.mock_call.return_value
        )

        self.make_msg.assert_called_once_with(
            'get_logical_device',
            pool_id='pool_id')

        self.mock_call.assert_called_once_with(
            mock.sentinel.context,
            self.make_msg.return_value
        )

    def test_pool_destroyed(self):
        self.assertEqual(
            self.api.pool_destroyed('pool_id'),
            self.mock_call.return_value
        )

        self.make_msg.assert_called_once_with(
            'pool_destroyed',
            pool_id='pool_id')

        self.mock_call.assert_called_once_with(
            mock.sentinel.context,
            self.make_msg.return_value
        )

    def test_pool_deployed(self):
        self.assertEqual(
            self.api.pool_deployed('pool_id'),
            self.mock_call.return_value
        )

        self.make_msg.assert_called_once_with(
            'pool_deployed',
            pool_id='pool_id')

        self.mock_call.assert_called_once_with(
            mock.sentinel.context,
            self.make_msg.return_value
        )

    def test_update_status(self):
        self.assertEqual(
            self.api.update_status('pool', 'pool_id', 'ACTIVE'),
            self.mock_call.return_value
        )

        self.make_msg.assert_called_once_with(
            'update_status',
            obj_type='pool',
            obj_id='pool_id',
            status='ACTIVE')

        self.mock_call.assert_called_once_with(
            mock.sentinel.context,
            self.make_msg.return_value,
        )

    def test_plug_vip_port(self):
        self.assertEqual(
            self.api.plug_vip_port('port_id'),
            self.mock_call.return_value
        )

        self.make_msg.assert_called_once_with(
            'plug_vip_port',
            port_id='port_id',
            host='host')

        self.mock_call.assert_called_once_with(
            mock.sentinel.context,
            self.make_msg.return_value
        )

    def test_unplug_vip_port(self):
        self.assertEqual(
            self.api.unplug_vip_port('port_id'),
            self.mock_call.return_value
        )

        self.make_msg.assert_called_once_with(
            'unplug_vip_port',
            port_id='port_id',
            host='host')

        self.mock_call.assert_called_once_with(
            mock.sentinel.context,
            self.make_msg.return_value
        )

    def test_update_pool_stats(self):
        self.assertEqual(
            self.api.update_pool_stats('pool_id', {'stat': 'stat'}),
            self.mock_call.return_value
        )

        self.make_msg.assert_called_once_with(
            'update_pool_stats',
            pool_id='pool_id',
            stats={'stat': 'stat'},
            host='host')

        self.mock_call.assert_called_once_with(
            mock.sentinel.context,
            self.make_msg.return_value
        )
