# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Cloudbase Solutions SRL
# Copyright 2013 Pedro Navarro Perez
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
Unit Tests for hyperv neutron rpc
"""

import mock

from neutron.agent import rpc as agent_rpc
from neutron.common import topics
from neutron.openstack.common import context
from neutron.openstack.common import rpc
from neutron.plugins.hyperv import agent_notifier_api as ana
from neutron.plugins.hyperv.common import constants
from neutron.tests import base


class rpcHyperVApiTestCase(base.BaseTestCase):

    def _test_hyperv_neutron_api(
            self, rpcapi, topic, method, rpc_method, **kwargs):
        ctxt = context.RequestContext('fake_user', 'fake_project')
        expected_retval = 'foo' if method == 'call' else None
        expected_msg = rpcapi.make_msg(method, **kwargs)
        expected_msg['version'] = rpcapi.BASE_RPC_API_VERSION
        if rpc_method == 'cast' and method == 'run_instance':
            kwargs['call'] = False

        with mock.patch.object(rpc, rpc_method) as rpc_method_mock:
            rpc_method_mock.return_value = expected_retval
            retval = getattr(rpcapi, method)(ctxt, **kwargs)

        self.assertEqual(retval, expected_retval)
        expected_args = [ctxt, topic, expected_msg]
        for arg, expected_arg in zip(rpc_method_mock.call_args[0],
                                     expected_args):
            self.assertEqual(arg, expected_arg)

    def test_delete_network(self):
        rpcapi = ana.AgentNotifierApi(topics.AGENT)
        self._test_hyperv_neutron_api(
            rpcapi,
            topics.get_topic_name(
                topics.AGENT,
                topics.NETWORK,
                topics.DELETE),
            'network_delete', rpc_method='fanout_cast',
            network_id='fake_request_spec')

    def test_port_update(self):
        rpcapi = ana.AgentNotifierApi(topics.AGENT)
        self._test_hyperv_neutron_api(
            rpcapi,
            topics.get_topic_name(
                topics.AGENT,
                topics.PORT,
                topics.UPDATE),
            'port_update', rpc_method='fanout_cast',
            port='fake_port',
            network_type='fake_network_type',
            segmentation_id='fake_segmentation_id',
            physical_network='fake_physical_network')

    def test_port_delete(self):
        rpcapi = ana.AgentNotifierApi(topics.AGENT)
        self._test_hyperv_neutron_api(
            rpcapi,
            topics.get_topic_name(
                topics.AGENT,
                topics.PORT,
                topics.DELETE),
            'port_delete', rpc_method='fanout_cast',
            port_id='port_id')

    def test_tunnel_update(self):
        rpcapi = ana.AgentNotifierApi(topics.AGENT)
        self._test_hyperv_neutron_api(
            rpcapi,
            topics.get_topic_name(
                topics.AGENT,
                constants.TUNNEL,
                topics.UPDATE),
            'tunnel_update', rpc_method='fanout_cast',
            tunnel_ip='fake_ip', tunnel_id='fake_id')

    def test_device_details(self):
        rpcapi = agent_rpc.PluginApi(topics.PLUGIN)
        self._test_hyperv_neutron_api(
            rpcapi, topics.PLUGIN,
            'get_device_details', rpc_method='call',
            device='fake_device',
            agent_id='fake_agent_id')

    def test_update_device_down(self):
        rpcapi = agent_rpc.PluginApi(topics.PLUGIN)
        self._test_hyperv_neutron_api(
            rpcapi, topics.PLUGIN,
            'update_device_down', rpc_method='call',
            device='fake_device',
            agent_id='fake_agent_id',
            host='fake_host')

    def test_tunnel_sync(self):
        rpcapi = agent_rpc.PluginApi(topics.PLUGIN)
        self._test_hyperv_neutron_api(
            rpcapi, topics.PLUGIN,
            'tunnel_sync', rpc_method='call',
            tunnel_ip='fake_tunnel_ip',
            tunnel_type=None)
