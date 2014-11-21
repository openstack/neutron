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

import contextlib
import copy
import mock

from neutron.services.loadbalancer.agent import agent_api as api
from neutron.tests import base


class TestApiCache(base.BaseTestCase):
    def setUp(self):
        super(TestApiCache, self).setUp()

        self.api = api.LbaasAgentApi('topic', mock.sentinel.context, 'host')

    def test_init(self):
        self.assertEqual(self.api.host, 'host')
        self.assertEqual(self.api.context, mock.sentinel.context)

    def _test_method(self, method, **kwargs):
        add_host = ('get_ready_devices', 'plug_vip_port', 'unplug_vip_port',
                    'update_pool_stats')
        expected_kwargs = copy.copy(kwargs)
        if method in add_host:
            expected_kwargs['host'] = self.api.host

        with contextlib.nested(
            mock.patch.object(self.api.client, 'call'),
            mock.patch.object(self.api.client, 'prepare'),
        ) as (
            rpc_mock, prepare_mock
        ):
            prepare_mock.return_value = self.api.client
            rpc_mock.return_value = 'foo'
            rv = getattr(self.api, method)(**kwargs)

        self.assertEqual(rv, 'foo')

        prepare_args = {}
        prepare_mock.assert_called_once_with(**prepare_args)

        rpc_mock.assert_called_once_with(mock.sentinel.context, method,
                                         **expected_kwargs)

    def test_get_ready_devices(self):
        self._test_method('get_ready_devices')

    def test_get_logical_device(self):
        self._test_method('get_logical_device', pool_id='pool_id')

    def test_pool_destroyed(self):
        self._test_method('pool_destroyed', pool_id='pool_id')

    def test_pool_deployed(self):
        self._test_method('pool_deployed', pool_id='pool_id')

    def test_update_status(self):
        self._test_method('update_status', obj_type='type', obj_id='id',
                          status='status')

    def test_plug_vip_port(self):
        self._test_method('plug_vip_port', port_id='port_id')

    def test_unplug_vip_port(self):
        self._test_method('unplug_vip_port', port_id='port_id')

    def test_update_pool_stats(self):
        self._test_method('update_pool_stats', pool_id='id', stats='stats')
