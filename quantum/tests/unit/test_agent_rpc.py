# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 OpenStack LLC.
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

import unittest

import mock

from quantum.agent import rpc
from quantum.openstack.common import cfg
from quantum.openstack.common import context


class AgentRPCPluginApi(unittest.TestCase):
    def _test_rpc_call(self, method):
        agent = rpc.PluginApi('fake_topic')
        ctxt = context.RequestContext('fake_user', 'fake_project')
        expect_val = 'foo'
        with mock.patch('quantum.openstack.common.rpc.call') as rpc_call:
            rpc_call.return_value = expect_val
            func_obj = getattr(agent, method)
            if method == 'tunnel_sync':
                actual_val = func_obj(ctxt, 'fake_tunnel_ip')
            else:
                actual_val = func_obj(ctxt, 'fake_device', 'fake_agent_id')
        self.assertEqual(actual_val, expect_val)

    def test_get_device_details(self):
        self._test_rpc_call('get_device_details')

    def test_update_device_down(self):
        self._test_rpc_call('update_device_down')

    def test_tunnel_sync(self):
        self._test_rpc_call('tunnel_sync')


class AgentRPCMethods(unittest.TestCase):
    def test_create_consumers(self):
        dispatcher = mock.Mock()
        expected = [
            mock.call(new=True),
            mock.call().create_consumer('foo-topic-op', dispatcher,
                                        fanout=True),
            mock.call().consume_in_thread()
        ]

        call_to_patch = 'quantum.openstack.common.rpc.create_connection'
        with mock.patch(call_to_patch) as create_connection:
            conn = rpc.create_consumers(dispatcher, 'foo', [('topic', 'op')])
            create_connection.assert_has_calls(expected)


class AgentRPCNotificationDispatcher(unittest.TestCase):
    def setUp(self):
        self.create_connection_p = mock.patch(
            'quantum.openstack.common.rpc.create_connection')
        self.create_connection = self.create_connection_p.start()
        cfg.CONF.set_override('default_notification_level', 'INFO')
        cfg.CONF.set_override('notification_topics', ['notifications'])

    def tearDown(self):
        self.create_connection_p.stop()
        cfg.CONF.reset()

    def test_init(self):
        nd = rpc.NotificationDispatcher()

        expected = [
            mock.call(new=True),
            mock.call().declare_topic_consumer(topic='notifications.info',
                                               queue_name=mock.ANY,
                                               callback=nd._add_to_queue),
            mock.call().consume_in_thread()
        ]
        self.create_connection.assert_has_calls(expected)

    def test_add_to_queue(self):
        nd = rpc.NotificationDispatcher()
        nd._add_to_queue('foo')
        self.assertEqual(nd.queue.get(), 'foo')

    def _test_run_dispatch_helper(self, msg, handler):
        msgs = [msg]

        def side_effect(*args):
            return msgs.pop(0)

        with mock.patch('eventlet.Queue.get') as queue_get:
            queue_get.side_effect = side_effect
            nd = rpc.NotificationDispatcher()
            # catch the assertion so that the loop runs once
            self.assertRaises(IndexError, nd.run_dispatch, handler)

    def test_run_dispatch_once(self):
        class SimpleHandler:
            def __init__(self):
                self.network_delete_end = mock.Mock()

        msg = dict(event_type='network.delete.end',
                   payload=dict(network_id='a'))

        handler = SimpleHandler()
        self._test_run_dispatch_helper(msg, handler)
        handler.network_delete_end.called_once_with(msg['payload'])

    def test_run_dispatch_missing_handler(self):
        class SimpleHandler:
            self.subnet_create_start = mock.Mock()

        msg = dict(event_type='network.delete.end',
                   payload=dict(network_id='a'))

        handler = SimpleHandler()

        with mock.patch('quantum.agent.rpc.LOG') as log:
            self._test_run_dispatch_helper(msg, handler)
            log.assert_has_calls([mock.call.debug(mock.ANY)])

    def test_run_dispatch_handler_raises(self):
        class SimpleHandler:
            def network_delete_end(self, payload):
                raise Exception('foo')

        msg = dict(event_type='network.delete.end',
                   payload=dict(network_id='a'))

        handler = SimpleHandler()

        with mock.patch('quantum.agent.rpc.LOG') as log:
            self._test_run_dispatch_helper(msg, handler)
            log.assert_has_calls([mock.call.warn(mock.ANY)])
