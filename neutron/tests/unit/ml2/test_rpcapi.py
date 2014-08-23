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

"""
Unit Tests for ml2 rpc
"""

import mock

from neutron.agent import rpc as agent_rpc
from neutron.common import exceptions
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.openstack.common import context
from neutron.plugins.ml2.drivers import type_tunnel
from neutron.plugins.ml2 import rpc as plugin_rpc
from neutron.tests import base


class RpcCallbacksTestCase(base.BaseTestCase):

    def setUp(self):
        super(RpcCallbacksTestCase, self).setUp()
        self.callbacks = plugin_rpc.RpcCallbacks(mock.Mock(), mock.Mock())
        self.manager = mock.patch.object(
            plugin_rpc.manager, 'NeutronManager').start()
        self.l3plugin = mock.Mock()
        self.manager.get_service_plugins.return_value = {
            'L3_ROUTER_NAT': self.l3plugin
        }

    def _test_update_device_up(self, extensions, kwargs):
        with mock.patch('neutron.plugins.ml2.plugin.Ml2Plugin'
                        '._device_to_port_id'):
            type(self.l3plugin).supported_extension_aliases = (
                mock.PropertyMock(return_value=extensions))
            self.callbacks.update_device_up(mock.ANY, **kwargs)

    def test_update_device_up_without_dvr(self):
        kwargs = {
            'agent_id': 'foo_agent',
            'device': 'foo_device'
        }
        self._test_update_device_up(['router'], kwargs)
        self.assertFalse(self.l3plugin.dvr_vmarp_table_update.call_count)

    def test_update_device_up_with_dvr(self):
        kwargs = {
            'agent_id': 'foo_agent',
            'device': 'foo_device'
        }
        self._test_update_device_up(['router', 'dvr'], kwargs)
        self.l3plugin.dvr_vmarp_table_update.assert_called_once_with(
            mock.ANY, mock.ANY, 'add')

    def test_update_device_up_with_dvr_when_port_not_found(self):
        kwargs = {
            'agent_id': 'foo_agent',
            'device': 'foo_device'
        }
        self.l3plugin.dvr_vmarp_table_update.side_effect = (
            exceptions.PortNotFound(port_id='foo_port_id'))
        self._test_update_device_up(['router', 'dvr'], kwargs)
        self.assertTrue(self.l3plugin.dvr_vmarp_table_update.call_count)


class RpcApiTestCase(base.BaseTestCase):

    def _test_rpc_api(self, rpcapi, topic, method, rpc_method, **kwargs):
        ctxt = context.RequestContext('fake_user', 'fake_project')
        expected_retval = 'foo' if method == 'call' else None
        expected_version = kwargs.pop('version', None)
        expected_msg = rpcapi.make_msg(method, **kwargs)
        if rpc_method == 'cast' and method == 'run_instance':
            kwargs['call'] = False

        rpc = n_rpc.RpcProxy
        with mock.patch.object(rpc, rpc_method) as rpc_method_mock:
            rpc_method_mock.return_value = expected_retval
            retval = getattr(rpcapi, method)(ctxt, **kwargs)

        self.assertEqual(retval, expected_retval)
        additional_args = {}
        if topic:
            additional_args['topic'] = topic
        if expected_version:
            additional_args['version'] = expected_version
        expected = [
            mock.call(ctxt, expected_msg, **additional_args)
        ]
        rpc_method_mock.assert_has_calls(expected)

    def test_delete_network(self):
        rpcapi = plugin_rpc.AgentNotifierApi(topics.AGENT)
        self._test_rpc_api(rpcapi,
                           topics.get_topic_name(topics.AGENT,
                                                 topics.NETWORK,
                                                 topics.DELETE),
                           'network_delete', rpc_method='fanout_cast',
                           network_id='fake_request_spec')

    def test_port_update(self):
        rpcapi = plugin_rpc.AgentNotifierApi(topics.AGENT)
        self._test_rpc_api(rpcapi,
                           topics.get_topic_name(topics.AGENT,
                                                 topics.PORT,
                                                 topics.UPDATE),
                           'port_update', rpc_method='fanout_cast',
                           port='fake_port',
                           network_type='fake_network_type',
                           segmentation_id='fake_segmentation_id',
                           physical_network='fake_physical_network')

    def test_tunnel_update(self):
        rpcapi = plugin_rpc.AgentNotifierApi(topics.AGENT)
        self._test_rpc_api(rpcapi,
                           topics.get_topic_name(topics.AGENT,
                                                 type_tunnel.TUNNEL,
                                                 topics.UPDATE),
                           'tunnel_update', rpc_method='fanout_cast',
                           tunnel_ip='fake_ip', tunnel_type='gre')

    def test_device_details(self):
        rpcapi = agent_rpc.PluginApi(topics.PLUGIN)
        self._test_rpc_api(rpcapi, None,
                           'get_device_details', rpc_method='call',
                           device='fake_device',
                           agent_id='fake_agent_id',
                           host='fake_host')

    def test_devices_details_list(self):
        rpcapi = agent_rpc.PluginApi(topics.PLUGIN)
        self._test_rpc_api(rpcapi, None,
                           'get_devices_details_list', rpc_method='call',
                           devices=['fake_device1', 'fake_device2'],
                           agent_id='fake_agent_id', host='fake_host',
                           version='1.3')

    def test_update_device_down(self):
        rpcapi = agent_rpc.PluginApi(topics.PLUGIN)
        self._test_rpc_api(rpcapi, None,
                           'update_device_down', rpc_method='call',
                           device='fake_device',
                           agent_id='fake_agent_id',
                           host='fake_host')

    def test_tunnel_sync(self):
        rpcapi = agent_rpc.PluginApi(topics.PLUGIN)
        self._test_rpc_api(rpcapi, None,
                           'tunnel_sync', rpc_method='call',
                           tunnel_ip='fake_tunnel_ip',
                           tunnel_type=None)

    def test_update_device_up(self):
        rpcapi = agent_rpc.PluginApi(topics.PLUGIN)
        self._test_rpc_api(rpcapi, None,
                           'update_device_up', rpc_method='call',
                           device='fake_device',
                           agent_id='fake_agent_id',
                           host='fake_host')
