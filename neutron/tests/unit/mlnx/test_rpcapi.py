# Copyright 2013 Mellanox Technologies, Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Unit Tests for Mellanox RPC (major reuse of linuxbridge rpc unit tests)
"""

import contextlib
import mock

from oslo.config import cfg
from oslo_context import context as oslo_context

from neutron.agent import rpc as agent_rpc
from neutron.common import topics
from neutron.plugins.mlnx import agent_notify_api
from neutron.tests import base


class rpcApiTestCase(base.BaseTestCase):

    def _test_mlnx_api(self, rpcapi, topic, method, rpc_method, **kwargs):
        ctxt = oslo_context.RequestContext('fake_user', 'fake_project')
        expected_retval = 'foo' if rpc_method == 'call' else None
        expected_version = kwargs.pop('version', None)
        fanout = kwargs.pop('fanout', False)

        with contextlib.nested(
            mock.patch.object(rpcapi.client, rpc_method),
            mock.patch.object(rpcapi.client, 'prepare'),
        ) as (
            rpc_mock, prepare_mock
        ):
            prepare_mock.return_value = rpcapi.client
            rpc_mock.return_value = expected_retval
            retval = getattr(rpcapi, method)(ctxt, **kwargs)

        prepare_args = {}
        if expected_version:
            prepare_args['version'] = expected_version
        if fanout:
            prepare_args['fanout'] = True
        if topic:
            prepare_args['topic'] = topic
        prepare_mock.assert_called_once_with(**prepare_args)

        if method == 'port_update':
            kwargs['segmentation_id'] = kwargs['vlan_id']
            if not cfg.CONF.AGENT.rpc_support_old_agents:
                del kwargs['vlan_id']

        self.assertEqual(retval, expected_retval)
        rpc_mock.assert_called_once_with(ctxt, method, **kwargs)

    def test_delete_network(self):
        rpcapi = agent_notify_api.AgentNotifierApi(topics.AGENT)
        self._test_mlnx_api(
                rpcapi,
                topics.get_topic_name(topics.AGENT,
                                      topics.NETWORK,
                                      topics.DELETE),
                'network_delete', rpc_method='cast', fanout=True,
                network_id='fake_request_spec')

    def test_port_update(self):
        cfg.CONF.set_override('rpc_support_old_agents', False, 'AGENT')
        rpcapi = agent_notify_api.AgentNotifierApi(topics.AGENT)
        self._test_mlnx_api(
                rpcapi,
                topics.get_topic_name(topics.AGENT,
                                      topics.PORT,
                                      topics.UPDATE),
                'port_update', rpc_method='cast', fanout=True,
                port='fake_port',
                network_type='vlan',
                physical_network='fake_net',
                vlan_id='fake_vlan_id')

    def test_port_update_old_agent(self):
        cfg.CONF.set_override('rpc_support_old_agents', True, 'AGENT')
        rpcapi = agent_notify_api.AgentNotifierApi(topics.AGENT)
        self._test_mlnx_api(
                rpcapi,
                topics.get_topic_name(topics.AGENT,
                                      topics.PORT,
                                      topics.UPDATE),
                'port_update', rpc_method='cast', fanout=True,
                port='fake_port',
                network_type='vlan',
                physical_network='fake_net',
                vlan_id='fake_vlan_id')

    def test_device_details(self):
        rpcapi = agent_rpc.PluginApi(topics.PLUGIN)
        self._test_mlnx_api(rpcapi, None,
                            'get_device_details', rpc_method='call',
                            device='fake_device',
                            agent_id='fake_agent_id',
                            host='fake_host')

    def test_devices_details_list(self):
        rpcapi = agent_rpc.PluginApi(topics.PLUGIN)
        self._test_mlnx_api(rpcapi, None,
                            'get_devices_details_list', rpc_method='call',
                            devices=['fake_device1', 'fake_device1'],
                            agent_id='fake_agent_id', host='fake_host',
                            version='1.3')

    def test_update_device_down(self):
        rpcapi = agent_rpc.PluginApi(topics.PLUGIN)
        self._test_mlnx_api(rpcapi, None,
                            'update_device_down', rpc_method='call',
                            device='fake_device',
                            agent_id='fake_agent_id',
                            host='fake_host')

    def test_update_device_up(self):
        rpcapi = agent_rpc.PluginApi(topics.PLUGIN)
        self._test_mlnx_api(rpcapi, None,
                            'update_device_up', rpc_method='call',
                            device='fake_device',
                            agent_id='fake_agent_id',
                            host='fake_host')
