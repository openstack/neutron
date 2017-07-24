# Copyright 2015 OpenStack Foundation.
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

import copy

import fixtures
import mock
from oslo_config import cfg
import oslo_messaging as messaging
from oslo_messaging import conffixture as messaging_conffixture
from oslo_messaging.rpc import dispatcher
import testtools

from neutron.common import rpc
from neutron.tests import base


CONF = cfg.CONF
CONF.import_opt('state_path', 'neutron.conf.common')


class RPCFixture(fixtures.Fixture):
    def _setUp(self):
        self.trans = copy.copy(rpc.TRANSPORT)
        self.noti_trans = copy.copy(rpc.NOTIFICATION_TRANSPORT)
        self.noti = copy.copy(rpc.NOTIFIER)
        self.all_mods = copy.copy(rpc.ALLOWED_EXMODS)
        self.ext_mods = copy.copy(rpc.EXTRA_EXMODS)
        self.addCleanup(self._reset_everything)

    def _reset_everything(self):
        rpc.TRANSPORT = self.trans
        rpc.NOTIFICATION_TRANSPORT = self.noti_trans
        rpc.NOTIFIER = self.noti
        rpc.ALLOWED_EXMODS = self.all_mods
        rpc.EXTRA_EXMODS = self.ext_mods


class TestRPC(base.DietTestCase):
    def setUp(self):
        super(TestRPC, self).setUp()
        self.useFixture(RPCFixture())

    @mock.patch.object(rpc, 'get_allowed_exmods')
    @mock.patch.object(rpc, 'RequestContextSerializer')
    @mock.patch.object(messaging, 'get_rpc_transport')
    @mock.patch.object(messaging, 'get_notification_transport')
    @mock.patch.object(messaging, 'Notifier')
    def test_init(self, mock_not, mock_noti_trans, mock_trans, mock_ser,
                  mock_exmods):
        notifier = mock.Mock()
        transport = mock.Mock()
        noti_transport = mock.Mock()
        serializer = mock.Mock()
        conf = mock.Mock()

        mock_exmods.return_value = ['foo']
        mock_trans.return_value = transport
        mock_noti_trans.return_value = noti_transport
        mock_ser.return_value = serializer
        mock_not.return_value = notifier

        rpc.init(conf)

        mock_exmods.assert_called_once_with()
        mock_trans.assert_called_once_with(conf, allowed_remote_exmods=['foo'])
        mock_noti_trans.assert_called_once_with(conf,
                                                allowed_remote_exmods=['foo'])
        mock_not.assert_called_once_with(noti_transport,
                                         serializer=serializer)
        self.assertIsNotNone(rpc.TRANSPORT)
        self.assertIsNotNone(rpc.NOTIFICATION_TRANSPORT)
        self.assertIsNotNone(rpc.NOTIFIER)

    def test_cleanup_transport_null(self):
        rpc.NOTIFIER = mock.Mock()
        rpc.NOTIFICATION_TRANSPORT = mock.Mock()
        self.assertRaises(AssertionError, rpc.cleanup)

    def test_cleanup_notification_transport_null(self):
        rpc.TRANSPORT = mock.Mock()
        rpc.NOTIFIER = mock.Mock()
        self.assertRaises(AssertionError, rpc.cleanup)

    def test_cleanup_notifier_null(self):
        rpc.TRANSPORT = mock.Mock()
        rpc.NOTIFICATION_TRANSPORT = mock.Mock()
        self.assertRaises(AssertionError, rpc.cleanup)

    def test_cleanup(self):
        rpc.NOTIFIER = mock.Mock()
        rpc.NOTIFICATION_TRANSPORT = mock.Mock()
        rpc.TRANSPORT = mock.Mock()
        trans_cleanup = mock.Mock()
        not_trans_cleanup = mock.Mock()
        rpc.TRANSPORT.cleanup = trans_cleanup
        rpc.NOTIFICATION_TRANSPORT.cleanup = not_trans_cleanup

        rpc.cleanup()

        trans_cleanup.assert_called_once_with()
        not_trans_cleanup.assert_called_once_with()
        self.assertIsNone(rpc.TRANSPORT)
        self.assertIsNone(rpc.NOTIFICATION_TRANSPORT)
        self.assertIsNone(rpc.NOTIFIER)

    def test_add_extra_exmods(self):
        rpc.EXTRA_EXMODS = []

        rpc.add_extra_exmods('foo', 'bar')

        self.assertEqual(['foo', 'bar'], rpc.EXTRA_EXMODS)

    def test_clear_extra_exmods(self):
        rpc.EXTRA_EXMODS = ['foo', 'bar']

        rpc.clear_extra_exmods()

        self.assertEqual(0, len(rpc.EXTRA_EXMODS))

    def test_get_allowed_exmods(self):
        rpc.ALLOWED_EXMODS = ['foo']
        rpc.EXTRA_EXMODS = ['bar']

        exmods = rpc.get_allowed_exmods()

        self.assertEqual(['foo', 'bar'], exmods)

    @mock.patch.object(rpc, 'RequestContextSerializer')
    @mock.patch.object(rpc, 'BackingOffClient')
    def test_get_client(self, mock_client, mock_ser):
        rpc.TRANSPORT = mock.Mock()
        tgt = mock.Mock()
        ser = mock.Mock()
        mock_client.return_value = 'client'
        mock_ser.return_value = ser

        client = rpc.get_client(tgt, version_cap='1.0', serializer='foo')

        mock_ser.assert_called_once_with('foo')
        mock_client.assert_called_once_with(rpc.TRANSPORT,
                                            tgt, version_cap='1.0',
                                            serializer=ser)
        self.assertEqual('client', client)

    @mock.patch.object(rpc, 'RequestContextSerializer')
    @mock.patch.object(messaging, 'get_rpc_server')
    def test_get_server(self, mock_get, mock_ser):
        rpc.TRANSPORT = mock.Mock()
        ser = mock.Mock()
        tgt = mock.Mock()
        ends = mock.Mock()
        mock_ser.return_value = ser
        mock_get.return_value = 'server'

        server = rpc.get_server(tgt, ends, serializer='foo')

        mock_ser.assert_called_once_with('foo')
        access_policy = dispatcher.DefaultRPCAccessPolicy
        mock_get.assert_called_once_with(rpc.TRANSPORT, tgt, ends,
                                         'eventlet', ser,
                                         access_policy=access_policy)
        self.assertEqual('server', server)

    def test_get_notifier(self):
        rpc.NOTIFIER = mock.Mock()
        mock_prep = mock.Mock()
        mock_prep.return_value = 'notifier'
        rpc.NOTIFIER.prepare = mock_prep

        notifier = rpc.get_notifier('service', publisher_id='foo')

        mock_prep.assert_called_once_with(publisher_id='foo')
        self.assertEqual('notifier', notifier)

    def test_get_notifier_null_publisher(self):
        rpc.NOTIFIER = mock.Mock()
        mock_prep = mock.Mock()
        mock_prep.return_value = 'notifier'
        rpc.NOTIFIER.prepare = mock_prep

        notifier = rpc.get_notifier('service', host='bar')

        mock_prep.assert_called_once_with(publisher_id='service.bar')
        self.assertEqual('notifier', notifier)


class TestRequestContextSerializer(base.DietTestCase):
    def setUp(self):
        super(TestRequestContextSerializer, self).setUp()
        self.mock_base = mock.Mock()
        self.ser = rpc.RequestContextSerializer(self.mock_base)
        self.ser_null = rpc.RequestContextSerializer(None)

    def test_serialize_entity(self):
        self.mock_base.serialize_entity.return_value = 'foo'

        ser_ent = self.ser.serialize_entity('context', 'entity')

        self.mock_base.serialize_entity.assert_called_once_with('context',
                                                                'entity')
        self.assertEqual('foo', ser_ent)

    def test_deserialize_entity(self):
        self.mock_base.deserialize_entity.return_value = 'foo'

        deser_ent = self.ser.deserialize_entity('context', 'entity')

        self.mock_base.deserialize_entity.assert_called_once_with('context',
                                                                  'entity')
        self.assertEqual('foo', deser_ent)

    def test_deserialize_entity_null_base(self):
        deser_ent = self.ser_null.deserialize_entity('context', 'entity')

        self.assertEqual('entity', deser_ent)

    def test_serialize_context(self):
        context = mock.Mock()

        self.ser.serialize_context(context)

        context.to_dict.assert_called_once_with()

    def test_deserialize_context(self):
        context_dict = {'foo': 'bar',
                        'user_id': 1,
                        'tenant_id': 1,
                        'is_admin': True}

        c = self.ser.deserialize_context(context_dict)

        self.assertEqual(1, c.user_id)
        self.assertEqual(1, c.project_id)

    def test_deserialize_context_no_user_id(self):
        context_dict = {'foo': 'bar',
                        'user': 1,
                        'tenant_id': 1,
                        'is_admin': True}

        c = self.ser.deserialize_context(context_dict)

        self.assertEqual(1, c.user_id)
        self.assertEqual(1, c.project_id)

    def test_deserialize_context_no_tenant_id(self):
        context_dict = {'foo': 'bar',
                        'user_id': 1,
                        'project_id': 1,
                        'is_admin': True}

        c = self.ser.deserialize_context(context_dict)

        self.assertEqual(1, c.user_id)
        self.assertEqual(1, c.project_id)

    def test_deserialize_context_no_ids(self):
        context_dict = {'foo': 'bar', 'is_admin': True}

        c = self.ser.deserialize_context(context_dict)

        self.assertIsNone(c.user_id)
        self.assertIsNone(c.project_id)


class ServiceTestCase(base.DietTestCase):
    # the class cannot be based on BaseTestCase since it mocks rpc.Connection

    def setUp(self):
        super(ServiceTestCase, self).setUp()
        self.host = 'foo'
        self.topic = 'neutron-agent'

        self.target_mock = mock.patch('oslo_messaging.Target')
        self.target_mock.start()

        self.messaging_conf = messaging_conffixture.ConfFixture(CONF)
        self.messaging_conf.transport_driver = 'fake'
        self.messaging_conf.response_timeout = 0
        self.useFixture(self.messaging_conf)

        self.addCleanup(rpc.cleanup)
        rpc.init(CONF)

    def test_operations(self):
        with mock.patch('oslo_messaging.get_rpc_server') as get_rpc_server:
            rpc_server = get_rpc_server.return_value

            service = rpc.Service(self.host, self.topic)
            service.start()
            rpc_server.start.assert_called_once_with()

            service.stop()
            rpc_server.stop.assert_called_once_with()
            rpc_server.wait.assert_called_once_with()


class TimeoutTestCase(base.DietTestCase):
    def setUp(self):
        super(TimeoutTestCase, self).setUp()

        self.messaging_conf = messaging_conffixture.ConfFixture(CONF)
        self.messaging_conf.transport_driver = 'fake'
        self.messaging_conf.response_timeout = 0
        self.useFixture(self.messaging_conf)

        self.addCleanup(rpc.cleanup)
        rpc.init(CONF)
        rpc.TRANSPORT = mock.MagicMock()
        rpc.TRANSPORT._send.side_effect = messaging.MessagingTimeout
        target = messaging.Target(version='1.0', topic='testing')
        self.client = rpc.get_client(target)
        self.call_context = mock.Mock()
        self.sleep = mock.patch('time.sleep').start()
        rpc.TRANSPORT.conf.rpc_response_timeout = 10

    def test_timeout_unaffected_when_explicitly_set(self):
        rpc.TRANSPORT.conf.rpc_response_timeout = 5
        ctx = self.client.prepare(topic='sandwiches', timeout=77)
        with testtools.ExpectedException(messaging.MessagingTimeout):
            ctx.call(self.call_context, 'create_pb_and_j')
        # ensure that the timeout was not increased and the back-off sleep
        # wasn't called
        self.assertEqual(
            5,
            rpc._BackingOffContextWrapper._METHOD_TIMEOUTS['create_pb_and_j'])
        self.assertFalse(self.sleep.called)

    def test_timeout_store_defaults(self):
        # any method should default to the configured timeout
        self.assertEqual(
            rpc.TRANSPORT.conf.rpc_response_timeout,
            rpc._BackingOffContextWrapper._METHOD_TIMEOUTS['method_1'])
        self.assertEqual(
            rpc.TRANSPORT.conf.rpc_response_timeout,
            rpc._BackingOffContextWrapper._METHOD_TIMEOUTS['method_2'])
        # a change to an existing should not affect new or existing ones
        rpc._BackingOffContextWrapper._METHOD_TIMEOUTS['method_2'] = 7000
        self.assertEqual(
            rpc.TRANSPORT.conf.rpc_response_timeout,
            rpc._BackingOffContextWrapper._METHOD_TIMEOUTS['method_1'])
        self.assertEqual(
            rpc.TRANSPORT.conf.rpc_response_timeout,
            rpc._BackingOffContextWrapper._METHOD_TIMEOUTS['method_3'])

    def test_method_timeout_sleep(self):
        rpc.TRANSPORT.conf.rpc_response_timeout = 2
        for i in range(100):
            with testtools.ExpectedException(messaging.MessagingTimeout):
                self.client.call(self.call_context, 'method_1')
            # sleep value should always be between 0 and configured timeout
            self.assertGreaterEqual(self.sleep.call_args_list[0][0][0], 0)
            self.assertLessEqual(self.sleep.call_args_list[0][0][0], 2)
            self.sleep.reset_mock()

    def test_method_timeout_increases_on_timeout_exception(self):
        rpc._BackingOffContextWrapper._METHOD_TIMEOUTS['method_1'] = 1
        for i in range(5):
            with testtools.ExpectedException(messaging.MessagingTimeout):
                self.client.call(self.call_context, 'method_1')

        # we only care to check the timeouts sent to the transport
        timeouts = [call[1]['timeout']
                    for call in rpc.TRANSPORT._send.call_args_list]
        self.assertEqual([1, 2, 4, 8, 16], timeouts)

    def test_method_timeout_10x_config_ceiling(self):
        rpc.TRANSPORT.conf.rpc_response_timeout = 10
        # 5 doublings should max out at the 10xdefault ceiling
        for i in range(5):
            with testtools.ExpectedException(messaging.MessagingTimeout):
                self.client.call(self.call_context, 'method_1')
        self.assertEqual(
            10 * rpc.TRANSPORT.conf.rpc_response_timeout,
            rpc._BackingOffContextWrapper._METHOD_TIMEOUTS['method_1'])
        with testtools.ExpectedException(messaging.MessagingTimeout):
            self.client.call(self.call_context, 'method_1')
        self.assertEqual(
            10 * rpc.TRANSPORT.conf.rpc_response_timeout,
            rpc._BackingOffContextWrapper._METHOD_TIMEOUTS['method_1'])

    def test_timeout_unchanged_on_other_exception(self):
        rpc._BackingOffContextWrapper._METHOD_TIMEOUTS['method_1'] = 1
        rpc.TRANSPORT._send.side_effect = ValueError
        with testtools.ExpectedException(ValueError):
            self.client.call(self.call_context, 'method_1')
        rpc.TRANSPORT._send.side_effect = messaging.MessagingTimeout
        with testtools.ExpectedException(messaging.MessagingTimeout):
            self.client.call(self.call_context, 'method_1')
        timeouts = [call[1]['timeout']
                    for call in rpc.TRANSPORT._send.call_args_list]
        self.assertEqual([1, 1], timeouts)

    def test_timeouts_for_methods_tracked_independently(self):
        rpc._BackingOffContextWrapper._METHOD_TIMEOUTS['method_1'] = 1
        rpc._BackingOffContextWrapper._METHOD_TIMEOUTS['method_2'] = 1
        for method in ('method_1', 'method_1', 'method_2',
                       'method_1', 'method_2'):
            with testtools.ExpectedException(messaging.MessagingTimeout):
                self.client.call(self.call_context, method)
        timeouts = [call[1]['timeout']
                    for call in rpc.TRANSPORT._send.call_args_list]
        self.assertEqual([1, 2, 1, 4, 2], timeouts)

    def test_timeouts_for_namespaces_tracked_independently(self):
        rpc._BackingOffContextWrapper._METHOD_TIMEOUTS['ns1.method'] = 1
        rpc._BackingOffContextWrapper._METHOD_TIMEOUTS['ns2.method'] = 1
        for ns in ('ns1', 'ns2'):
            self.client.target.namespace = ns
            for i in range(4):
                with testtools.ExpectedException(messaging.MessagingTimeout):
                    self.client.call(self.call_context, 'method')
        timeouts = [call[1]['timeout']
                    for call in rpc.TRANSPORT._send.call_args_list]
        self.assertEqual([1, 2, 4, 8, 1, 2, 4, 8], timeouts)

    def test_method_timeout_increases_with_prepare(self):
        rpc._BackingOffContextWrapper._METHOD_TIMEOUTS['method_1'] = 1
        ctx = self.client.prepare(version='1.4')
        with testtools.ExpectedException(messaging.MessagingTimeout):
            ctx.call(self.call_context, 'method_1')
        with testtools.ExpectedException(messaging.MessagingTimeout):
            ctx.call(self.call_context, 'method_1')

        # we only care to check the timeouts sent to the transport
        timeouts = [call[1]['timeout']
                    for call in rpc.TRANSPORT._send.call_args_list]
        self.assertEqual([1, 2], timeouts)

    def test_set_max_timeout_caps_all_methods(self):
        rpc.TRANSPORT.conf.rpc_response_timeout = 300
        rpc._BackingOffContextWrapper._METHOD_TIMEOUTS['method_1'] = 100
        rpc.BackingOffClient.set_max_timeout(50)
        # both explicitly tracked
        self.assertEqual(
            50, rpc._BackingOffContextWrapper._METHOD_TIMEOUTS['method_1'])
        # as well as new methods
        self.assertEqual(
            50, rpc._BackingOffContextWrapper._METHOD_TIMEOUTS['method_2'])

    def test_set_max_timeout_retains_lower_timeouts(self):
        rpc._BackingOffContextWrapper._METHOD_TIMEOUTS['method_1'] = 10
        rpc.BackingOffClient.set_max_timeout(50)
        self.assertEqual(
            10, rpc._BackingOffContextWrapper._METHOD_TIMEOUTS['method_1'])

    def test_set_max_timeout_overrides_default_timeout(self):
        rpc.TRANSPORT.conf.rpc_response_timeout = 10
        self.assertEqual(
            10 * 10, rpc._BackingOffContextWrapper.get_max_timeout())
        rpc._BackingOffContextWrapper.set_max_timeout(10)
        self.assertEqual(10, rpc._BackingOffContextWrapper.get_max_timeout())


class CastExceptionTestCase(base.DietTestCase):
    def setUp(self):
        super(CastExceptionTestCase, self).setUp()

        self.messaging_conf = messaging_conffixture.ConfFixture(CONF)
        self.messaging_conf.transport_driver = 'fake'
        self.messaging_conf.response_timeout = 0
        self.useFixture(self.messaging_conf)

        self.addCleanup(rpc.cleanup)
        rpc.init(CONF)
        rpc.TRANSPORT = mock.MagicMock()
        rpc.TRANSPORT._send.side_effect = Exception
        target = messaging.Target(version='1.0', topic='testing')
        self.client = rpc.get_client(target)
        self.cast_context = mock.Mock()

    def test_cast_catches_exception(self):
        self.client.cast(self.cast_context, 'method_1')


class TestConnection(base.DietTestCase):
    def setUp(self):
        super(TestConnection, self).setUp()
        self.conn = rpc.Connection()

    @mock.patch.object(messaging, 'Target')
    @mock.patch.object(cfg, 'CONF')
    @mock.patch.object(rpc, 'get_server')
    def test_create_consumer(self, mock_get, mock_cfg, mock_tgt):
        mock_cfg.host = 'foo'
        server = mock.Mock()
        target = mock.Mock()
        mock_get.return_value = server
        mock_tgt.return_value = target

        self.conn.create_consumer('topic', 'endpoints', fanout=True)

        mock_tgt.assert_called_once_with(topic='topic', server='foo',
                                         fanout=True)
        mock_get.assert_called_once_with(target, 'endpoints')
        self.assertEqual([server], self.conn.servers)

    def test_consume_in_threads(self):
        self.conn.servers = [mock.Mock(), mock.Mock()]

        servs = self.conn.consume_in_threads()

        for serv in self.conn.servers:
            serv.start.assert_called_once_with()
        self.assertEqual(servs, self.conn.servers)

    def test_close(self):
        self.conn.servers = [mock.Mock(), mock.Mock()]

        self.conn.close()

        for serv in self.conn.servers:
            serv.stop.assert_called_once_with()
            serv.wait.assert_called_once_with()
