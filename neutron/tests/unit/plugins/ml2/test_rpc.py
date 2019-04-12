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

import collections

import mock
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib.services.qos import constants as qos_consts
from oslo_config import cfg
from oslo_context import context as oslo_context
from sqlalchemy.orm import exc

from neutron.agent import rpc as agent_rpc
from neutron.common import topics
from neutron.db import provisioning_blocks
from neutron.plugins.ml2 import db as ml2_db
from neutron.plugins.ml2.drivers import type_tunnel
from neutron.plugins.ml2 import managers
from neutron.plugins.ml2 import rpc as plugin_rpc
from neutron.tests import base


cfg.CONF.import_group('ml2', 'neutron.conf.plugins.ml2.config')


class RpcCallbacksTestCase(base.BaseTestCase):

    def setUp(self):
        super(RpcCallbacksTestCase, self).setUp()
        self.type_manager = managers.TypeManager()
        self.notifier = plugin_rpc.AgentNotifierApi(topics.AGENT)
        self.callbacks = plugin_rpc.RpcCallbacks(self.notifier,
                                                 self.type_manager)
        self.plugin = mock.MagicMock()
        directory.add_plugin(plugin_constants.CORE, self.plugin)

    def _test_update_device_up(self, host=None):
        kwargs = {
            'agent_id': 'foo_agent',
            'device': 'foo_device',
            'host': host
        }
        with mock.patch('neutron.plugins.ml2.plugin.Ml2Plugin'
                        '._device_to_port_id'),\
            mock.patch.object(self.callbacks, 'notify_l2pop_port_wiring'):
            with mock.patch('neutron.db.provisioning_blocks.'
                            'provisioning_complete') as pc:
                self.callbacks.update_device_up(mock.Mock(), **kwargs)
                return pc

    def test_update_device_up_notify(self):
        notify = self._test_update_device_up()
        notify.assert_called_once_with(mock.ANY, mock.ANY, resources.PORT,
                                       provisioning_blocks.L2_AGENT_ENTITY)

    def test_update_device_up_notify_not_sent_with_port_not_found(self):
        self.plugin.port_bound_to_host.return_value = False
        notify = self._test_update_device_up('host')
        self.assertFalse(notify.call_count)

    def test_get_device_details_without_port_context(self):
        self.plugin.get_bound_port_context.return_value = None
        self.assertEqual(
            {'device': 'fake_device'},
            self.callbacks.get_device_details(mock.Mock(),
                                              device='fake_device'))

    def test_get_device_details_port_context_without_bounded_segment(self):
        self.plugin.get_bound_port_context().bottom_bound_segment = None
        self.assertEqual(
            {'device': 'fake_device'},
            self.callbacks.get_device_details(mock.Mock(),
                                              device='fake_device'))

    def test_get_device_details_port_status_equal_new_status(self):
        port = collections.defaultdict(lambda: 'fake')
        self.plugin.get_bound_port_context().current = port
        self.plugin.port_bound_to_host = port
        for admin_state_up in (True, False):
            new_status = (constants.PORT_STATUS_BUILD if admin_state_up
                          else constants.PORT_STATUS_DOWN)
            for status in (constants.PORT_STATUS_ACTIVE,
                           constants.PORT_STATUS_BUILD,
                           constants.PORT_STATUS_DOWN,
                           constants.PORT_STATUS_ERROR):
                port['admin_state_up'] = admin_state_up
                port['status'] = status
                self.plugin.update_port_status.reset_mock()
                self.callbacks.get_device_details(mock.Mock())
                self.assertEqual(status == new_status,
                                 not self.plugin.update_port_status.called)

    def test_get_device_details_caching(self):
        port = collections.defaultdict(lambda: 'fake_port')
        cached_networks = {}
        self.plugin.get_bound_port_context().current = port
        self.plugin.get_bound_port_context().network.current = (
            {"id": "fake_network"})
        self.callbacks.get_device_details(mock.Mock(), host='fake_host',
                                          cached_networks=cached_networks)
        self.assertIn('fake_port', cached_networks)

    def test_get_device_details_wrong_host(self):
        port = collections.defaultdict(lambda: 'fake')
        port_context = self.plugin.get_bound_port_context()
        port_context.current = port
        port_context.host = 'fake'
        self.plugin.update_port_status.reset_mock()
        self.callbacks.get_device_details(mock.Mock(),
                                          host='fake_host')
        self.assertFalse(self.plugin.update_port_status.called)

    def test_get_device_details_port_no_host(self):
        port = collections.defaultdict(lambda: 'fake')
        port_context = self.plugin.get_bound_port_context()
        port_context.current = port
        self.plugin.update_port_status.reset_mock()
        self.callbacks.get_device_details(mock.Mock())
        self.assertTrue(self.plugin.update_port_status.called)

    def test_get_device_details_qos_policy_id_none(self):
        port = collections.defaultdict(lambda: 'fake_port')
        self.plugin.get_bound_port_context().current = port
        self.plugin.get_bound_port_context().network._network = (
            {"id": "fake_network"})
        res = self.callbacks.get_device_details(mock.Mock(), host='fake')
        self.assertIsNone(res['qos_policy_id'])

    def test_get_device_details_network_qos_policy_id(self):
        port = collections.defaultdict(lambda: 'fake_port')
        self.plugin.get_bound_port_context().current = port
        self.plugin.get_bound_port_context().network._network = (
            {"id": "fake_network",
             qos_consts.QOS_POLICY_ID: 'test-policy-id'})
        res = self.callbacks.get_device_details(mock.Mock(), host='fake')
        self.assertEqual('test-policy-id', res['network_qos_policy_id'])

    def test_get_device_details_qos_policy_id_from_port(self):
        port = collections.defaultdict(
            lambda: 'fake_port',
            {qos_consts.QOS_POLICY_ID: 'test-port-policy-id'})
        self.plugin.get_bound_port_context().current = port
        self.plugin.get_bound_port_context().network._network = (
            {"id": "fake_network",
             qos_consts.QOS_POLICY_ID: 'test-net-policy-id'})
        res = self.callbacks.get_device_details(mock.Mock(), host='fake')
        self.assertEqual('test-port-policy-id', res['qos_policy_id'])

    def _test_get_devices_list(self, callback, side_effect, expected):
        devices = [1, 2, 3, 4, 5]
        kwargs = {'host': 'fake_host', 'agent_id': 'fake_agent_id'}
        with mock.patch.object(self.callbacks, '_get_device_details',
                               side_effect=side_effect) as f:
            res = callback('fake_context', devices=devices, **kwargs)
            self.assertEqual(expected, res)
            self.assertEqual(len(devices), f.call_count)
            calls = [mock.call('fake_context', device=i,
                               port_context=mock.ANY, **kwargs)
                     for i in devices]
            f.assert_has_calls(calls)

    def test_get_devices_details_list(self):
        results = [{'device': [v]} for v in [1, 2, 3, 4, 5]]
        expected = results
        callback = self.callbacks.get_devices_details_list
        self._test_get_devices_list(callback, results, expected)

    def test_get_devices_details_list_with_empty_devices(self):
        with mock.patch.object(self.callbacks, 'get_device_details') as f:
            res = self.callbacks.get_devices_details_list('fake_context')
            self.assertFalse(f.called)
            self.assertEqual([], res)

    def test_get_devices_details_list_and_failed_devices(self):
        devices = [1, 2, 3, 4, 5]
        expected = {'devices': devices, 'failed_devices': []}
        callback = (
            self.callbacks.get_devices_details_list_and_failed_devices)
        self._test_get_devices_list(callback, devices, expected)

    def test_get_devices_details_list_and_failed_devices_failures(self):
        devices = [1, Exception('testdevice'), 3,
                   Exception('testdevice'), 5]
        expected = {'devices': [1, 3, 5], 'failed_devices': [2, 4]}
        callback = (
            self.callbacks.get_devices_details_list_and_failed_devices)
        self._test_get_devices_list(callback, devices, expected)

    def test_get_devices_details_list_and_failed_devices_empty_dev(self):
        with mock.patch.object(self.callbacks, 'get_device_details') as f:
            res = self.callbacks.get_devices_details_list_and_failed_devices(
                'fake_context')
            self.assertFalse(f.called)
            self.assertEqual({'devices': [], 'failed_devices': []}, res)

    def _test_update_device_not_bound_to_host(self, func):
        self.plugin.port_bound_to_host.return_value = False
        self.callbacks.notify_l2pop_port_wiring = mock.Mock()
        self.plugin._device_to_port_id.return_value = 'fake_port_id'
        res = func(mock.Mock(), device='fake_device', host='fake_host')
        self.plugin.port_bound_to_host.assert_called_once_with(mock.ANY,
                                                               'fake_port_id',
                                                               'fake_host')
        return res

    def test_update_device_up_with_device_not_bound_to_host(self):
        with mock.patch.object(ml2_db, 'get_port') as ml2_db_get_port:
            self.assertIsNone(self._test_update_device_not_bound_to_host(
                self.callbacks.update_device_up))
            port = ml2_db_get_port.return_value
            (self.plugin.nova_notifier.notify_port_active_direct.
             assert_called_once_with(port))

    def test_update_device_down_with_device_not_bound_to_host(self):
        self.assertEqual(
            {'device': 'fake_device', 'exists': True},
            self._test_update_device_not_bound_to_host(
                self.callbacks.update_device_down))

    def test_update_device_down_call_update_port_status(self):
        self.plugin.update_port_status.return_value = False
        self.callbacks.notify_l2pop_port_wiring = mock.Mock()
        self.plugin._device_to_port_id.return_value = 'fake_port_id'
        self.assertEqual(
            {'device': 'fake_device', 'exists': False},
            self.callbacks.update_device_down(mock.Mock(),
                                              device='fake_device',
                                              host='fake_host'))
        self.plugin.update_port_status.assert_called_once_with(
            mock.ANY, 'fake_port_id', constants.PORT_STATUS_DOWN,
            'fake_host')

    def test_update_device_down_call_update_port_status_failed(self):
        self.plugin.update_port_status.side_effect = exc.StaleDataError
        self.assertEqual({'device': 'fake_device', 'exists': False},
                         self.callbacks.update_device_down(
                             mock.Mock(), device='fake_device'))

    def _test_update_device_list(self, devices_up_side_effect,
                                 devices_down_side_effect, expected):
        devices_up = [1, 2, 3]
        devices_down = [4, 5]
        kwargs = {'host': 'fake_host', 'agent_id': 'fake_agent_id'}
        with mock.patch.object(self.callbacks, 'update_device_up',
                               side_effect=devices_up_side_effect) as f_up, \
            mock.patch.object(self.callbacks, 'update_device_down',
                              side_effect=devices_down_side_effect) as f_down:
            res = self.callbacks.update_device_list(
                'fake_context', devices_up=devices_up,
                devices_down=devices_down, **kwargs)
            self.assertEqual(expected, res)
            self.assertEqual(len(devices_up), f_up.call_count)
            self.assertEqual(len(devices_down), f_down.call_count)

    def test_update_device_list_no_failure(self):
        devices_up_side_effect = [1, 2, 3]
        devices_down_side_effect = [
             {'device': 4, 'exists': True},
             {'device': 5, 'exists': True}]
        expected = {'devices_up': devices_up_side_effect,
                    'failed_devices_up': [],
                    'devices_down':
                        [{'device': 4, 'exists': True},
                         {'device': 5, 'exists': True}],
                    'failed_devices_down': []}
        self._test_update_device_list(devices_up_side_effect,
                                      devices_down_side_effect,
                                      expected)

    def test_update_device_list_failed_devices(self):

        devices_up_side_effect = [1, Exception('testdevice'), 3]
        devices_down_side_effect = [{'device': 4, 'exists': True},
                        Exception('testdevice')]
        expected = {'devices_up': [1, 3],
                    'failed_devices_up': [2],
                    'devices_down':
                        [{'device': 4, 'exists': True}],
                    'failed_devices_down': [5]}

        self._test_update_device_list(devices_up_side_effect,
                                      devices_down_side_effect,
                                      expected)

    def test_update_device_list_empty_devices(self):

        expected = {'devices_up': [],
                    'failed_devices_up': [],
                    'devices_down': [],
                    'failed_devices_down': []}

        kwargs = {'host': 'fake_host', 'agent_id': 'fake_agent_id'}
        res = self.callbacks.update_device_list(
            'fake_context', devices_up=[], devices_down=[], **kwargs)
        self.assertEqual(expected, res)


class RpcApiTestCase(base.BaseTestCase):

    def _test_rpc_api(self, rpcapi, topic, method, rpc_method, **kwargs):
        if method == "update_device_list":
            expected = {'devices_up': [],
                        'failed_devices_up': [],
                        'devices_down': [],
                        'failed_devices_down': []}
        else:
            expected = 'foo'

        ctxt = oslo_context.RequestContext(user='fake_user',
                                           tenant='fake_project')
        expected_retval = expected if rpc_method == 'call' else None
        expected_version = kwargs.pop('version', None)
        fanout = kwargs.pop('fanout', False)

        with mock.patch.object(rpcapi.client, rpc_method) as rpc_mock,\
                mock.patch.object(rpcapi.client, 'prepare') as prepare_mock:
            prepare_mock.return_value = rpcapi.client
            rpc_mock.return_value = expected_retval
            retval = getattr(rpcapi, method)(ctxt, **kwargs)

        prepare_args = {}
        if expected_version:
            prepare_args['version'] = expected_version
        if fanout:
            prepare_args['fanout'] = fanout
        if topic:
            prepare_args['topic'] = topic
        prepare_mock.assert_called_once_with(**prepare_args)

        self.assertEqual(retval, expected_retval)
        rpc_mock.assert_called_once_with(ctxt, method, **kwargs)

    def test_delete_network(self):
        rpcapi = plugin_rpc.AgentNotifierApi(topics.AGENT)
        self._test_rpc_api(
                rpcapi,
                topics.get_topic_name(topics.AGENT,
                                      topics.NETWORK,
                                      topics.DELETE),
                'network_delete', rpc_method='cast',
                fanout=True, network_id='fake_request_spec')

    def test_port_update(self):
        rpcapi = plugin_rpc.AgentNotifierApi(topics.AGENT)
        self._test_rpc_api(
                rpcapi,
                topics.get_topic_name(topics.AGENT,
                                      topics.PORT,
                                      topics.UPDATE),
                'port_update', rpc_method='cast',
                fanout=True, port='fake_port',
                network_type='fake_network_type',
                segmentation_id='fake_segmentation_id',
                physical_network='fake_physical_network')

    def test_port_delete(self):
        rpcapi = plugin_rpc.AgentNotifierApi(topics.AGENT)
        self._test_rpc_api(
            rpcapi,
            topics.get_topic_name(topics.AGENT,
                                  topics.PORT,
                                  topics.DELETE),
            'port_delete', rpc_method='cast',
            fanout=True, port_id='fake_port')

    def test_tunnel_update(self):
        rpcapi = plugin_rpc.AgentNotifierApi(topics.AGENT)
        self._test_rpc_api(
                rpcapi,
                topics.get_topic_name(topics.AGENT,
                                      type_tunnel.TUNNEL,
                                      topics.UPDATE),
                'tunnel_update', rpc_method='cast',
                fanout=True,
                tunnel_ip='fake_ip', tunnel_type='gre')

    def test_tunnel_delete(self):
        rpcapi = plugin_rpc.AgentNotifierApi(topics.AGENT)
        self._test_rpc_api(
                rpcapi,
                topics.get_topic_name(topics.AGENT,
                                      type_tunnel.TUNNEL,
                                      topics.DELETE),
                'tunnel_delete', rpc_method='cast',
                fanout=True,
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
                           tunnel_type=None,
                           host='fake_host',
                           version='1.4')

    def test_update_device_up(self):
        rpcapi = agent_rpc.PluginApi(topics.PLUGIN)
        self._test_rpc_api(rpcapi, None,
                           'update_device_up', rpc_method='call',
                           device='fake_device',
                           agent_id='fake_agent_id',
                           host='fake_host')

    def test_update_device_list(self):
        rpcapi = agent_rpc.PluginApi(topics.PLUGIN)
        self._test_rpc_api(rpcapi, None,
                           'update_device_list', rpc_method='call',
                           devices_up=['fake_device1', 'fake_device2'],
                           devices_down=['fake_device3', 'fake_device4'],
                           agent_id='fake_agent_id',
                           host='fake_host',
                           agent_restarted=False,
                           version='1.5')

    def test_get_devices_details_list_and_failed_devices(self):
        rpcapi = agent_rpc.PluginApi(topics.PLUGIN)
        self._test_rpc_api(rpcapi, None,
                           'get_devices_details_list_and_failed_devices',
                           rpc_method='call',
                           devices=['fake_device1', 'fake_device2'],
                           agent_id='fake_agent_id',
                           host='fake_host',
                           version='1.5')

    def test_devices_details_list_and_failed_devices(self):
        rpcapi = agent_rpc.PluginApi(topics.PLUGIN)
        self._test_rpc_api(rpcapi, None,
                           'get_devices_details_list_and_failed_devices',
                           rpc_method='call',
                           devices=['fake_device1', 'fake_device2'],
                           agent_id='fake_agent_id', host='fake_host',
                           version='1.5')
