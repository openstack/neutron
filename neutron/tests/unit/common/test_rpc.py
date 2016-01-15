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

from neutron.common import rpc
from neutron import context
from neutron.tests import base


CONF = cfg.CONF
CONF.import_opt('state_path', 'neutron.common.config')


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
    @mock.patch.object(messaging, 'get_transport')
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
        mock_trans.assert_called_once_with(conf, allowed_remote_exmods=['foo'],
                                           aliases=rpc.TRANSPORT_ALIASES)
        mock_noti_trans.assert_called_once_with(conf,
                                                allowed_remote_exmods=['foo'],
                                                aliases=rpc.TRANSPORT_ALIASES)
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
    @mock.patch.object(messaging, 'RPCClient')
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
        mock_get.assert_called_once_with(rpc.TRANSPORT, tgt, ends,
                                         'eventlet', ser)
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

    @mock.patch.object(context, 'Context')
    def test_deserialize_context(self, mock_con):
        context = mock.Mock()
        context.copy.return_value = {'foo': 'bar',
                                     'user_id': 1,
                                     'tenant_id': 1}

        self.ser.deserialize_context(context)
        mock_con.assert_called_once_with(1, 1, foo='bar')

    @mock.patch.object(context, 'Context')
    def test_deserialize_context_no_user_id(self, mock_con):
        context = mock.Mock()
        context.copy.return_value = {'foo': 'bar',
                                     'user': 1,
                                     'tenant_id': 1}

        self.ser.deserialize_context(context)
        mock_con.assert_called_once_with(1, 1, foo='bar')

    @mock.patch.object(context, 'Context')
    def test_deserialize_context_no_tenant_id(self, mock_con):
        context = mock.Mock()
        context.copy.return_value = {'foo': 'bar',
                                     'user_id': 1,
                                     'project_id': 1}

        self.ser.deserialize_context(context)
        mock_con.assert_called_once_with(1, 1, foo='bar')

    @mock.patch.object(context, 'Context')
    def test_deserialize_context_no_ids(self, mock_con):
        context = mock.Mock()
        context.copy.return_value = {'foo': 'bar'}

        self.ser.deserialize_context(context)
        mock_con.assert_called_once_with(None, None, foo='bar')


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
