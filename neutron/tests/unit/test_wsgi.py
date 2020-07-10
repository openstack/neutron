# Copyright 2013 OpenStack Foundation.
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

import os
import socket
import ssl
from unittest import mock
import urllib

from neutron_lib.db import api as db_api
from neutron_lib import exceptions as exception
from oslo_config import cfg
from oslo_utils import netutils
import testtools
import webob
import webob.exc

from neutron.tests import base
from neutron import wsgi

CONF = cfg.CONF

TEST_VAR_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__),
                               '..', 'var'))


def open_no_proxy(*args, **kwargs):
    # NOTE(jamespage):
    # Deal with more secure certification chain verification
    # introduced in python 2.7.9 under PEP-0476
    # https://github.com/python/peps/blob/master/pep-0476.txt
    if hasattr(ssl, "_create_unverified_context"):
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(
                context=ssl._create_unverified_context())
        )
    else:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    return opener.open(*args, **kwargs)


class TestServiceBase(base.BaseTestCase):
    """Service tests base."""

    @mock.patch("neutron.policy.refresh")
    @mock.patch("neutron.common.config.setup_logging")
    def _test_reset(self, worker_service, setup_logging_mock, refresh_mock):
        worker_service.reset()

        setup_logging_mock.assert_called_once_with()
        refresh_mock.assert_called_once_with()


class TestWorkerService(TestServiceBase):
    """WorkerService tests."""

    @mock.patch.object(db_api, 'get_context_manager')
    def test_start_withoutdb_call(self, apimock):
        _service = mock.Mock()
        _service.pool.spawn.return_value = None

        _app = mock.Mock()
        workerservice = wsgi.WorkerService(_service, _app, "on")
        workerservice.start()
        self.assertFalse(apimock.called)

    def test_reset(self):
        _service = mock.Mock()
        _app = mock.Mock()

        worker_service = wsgi.WorkerService(_service, _app, "on")
        self._test_reset(worker_service)


class TestWSGIServer(base.BaseTestCase):
    """WSGI server tests."""

    def test_start_random_port(self):
        server = wsgi.Server("test_random_port")
        server.start(None, 0, host="127.0.0.1")
        self.assertNotEqual(0, server.port)
        server.stop()
        server.wait()

    @mock.patch('oslo_service.service.ProcessLauncher')
    def test_start_multiple_workers(self, ProcessLauncher):
        launcher = ProcessLauncher.return_value

        server = wsgi.Server("test_multiple_processes")
        server.start(None, 0, host="127.0.0.1", workers=2)
        launcher.launch_service.assert_called_once_with(mock.ANY, workers=2)

        server.stop()
        launcher.stop.assert_called_once_with()

        server.wait()
        launcher.wait.assert_called_once_with()

    @testtools.skipIf(
        not netutils.is_ipv6_enabled(),
        'IPv6 support disabled on host')
    def test_start_random_port_with_ipv6(self):
        server = wsgi.Server("test_random_port")
        server.start(None, 0, host="::1")
        self.assertEqual("::1", server.host)
        self.assertNotEqual(0, server.port)
        server.stop()
        server.wait()

    def test_ipv6_listen_called_with_scope(self):
        server = wsgi.Server("test_app")

        with mock.patch.object(wsgi.eventlet, 'listen') as mock_listen:
            with mock.patch.object(socket, 'getaddrinfo') as mock_get_addr:
                mock_get_addr.return_value = [
                    (socket.AF_INET6,
                     socket.SOCK_STREAM,
                     socket.IPPROTO_TCP,
                     '',
                     ('fe80::204:acff:fe96:da87%eth0', 1234, 0, 2))
                ]
                with mock.patch.object(server, 'pool') as mock_pool:
                    server.start(None,
                                 1234,
                                 host="fe80::204:acff:fe96:da87%eth0")

                    mock_get_addr.assert_called_once_with(
                        "fe80::204:acff:fe96:da87%eth0",
                        1234,
                        socket.AF_UNSPEC,
                        socket.SOCK_STREAM
                    )

                    mock_listen.assert_called_once_with(
                        ('fe80::204:acff:fe96:da87%eth0', 1234, 0, 2),
                        family=socket.AF_INET6,
                        backlog=cfg.CONF.backlog
                    )

                    mock_pool.spawn.assert_has_calls([
                        mock.call(
                            server._run,
                            None,
                            mock_listen.return_value.dup.return_value)
                    ])

    def test_app(self):
        greetings = b'Hello, World!!!'

        def hello_world(env, start_response):
            if env['PATH_INFO'] != '/':
                start_response('404 Not Found',
                               [('Content-Type', 'text/plain')])
                return ['Not Found\r\n']
            start_response('200 OK', [('Content-Type', 'text/plain')])
            return [greetings]

        server = wsgi.Server("test_app")
        server.start(hello_world, 0, host="127.0.0.1")

        response = open_no_proxy('http://127.0.0.1:%d/' % server.port)

        self.assertEqual(greetings, response.read())

        server.stop()

    def test_disable_ssl(self):
        CONF.set_default('use_ssl', True)

        greetings = 'Hello, World!!!'

        def hello_world(env, start_response):
            if env['PATH_INFO'] != '/':
                start_response('404 Not Found',
                               [('Content-Type', 'text/plain')])
                return ['Not Found\r\n']
            start_response('200 OK', [('Content-Type', 'text/plain')])
            return [greetings]

        server = wsgi.Server("test_app", disable_ssl=True)
        server.start(hello_world, 0, host="127.0.0.1")

        response = open_no_proxy('http://127.0.0.1:%d/' % server.port)

        self.assertEqual(greetings.encode('utf-8'), response.read())

        server.stop()

    @mock.patch.object(wsgi, 'eventlet')
    def test__run(self, eventlet_mock):
        server = wsgi.Server('test')
        server._run("app", "socket")
        eventlet_mock.wsgi.server.assert_called_once_with(
            'socket',
            'app',
            max_size=server.num_threads,
            log=mock.ANY,
            keepalive=CONF.wsgi_keep_alive,
            log_format=CONF.wsgi_log_format,
            socket_timeout=server.client_socket_timeout
        )


class SerializerTest(base.BaseTestCase):
    def test_serialize_unknown_content_type(self):
        """Verify that exception InvalidContentType is raised."""
        input_dict = {'servers': {'test': 'pass'}}
        content_type = 'application/unknown'
        serializer = wsgi.Serializer()

        self.assertRaises(
            exception.InvalidContentType, serializer.serialize,
            input_dict, content_type)

    def test_get_deserialize_handler_unknown_content_type(self):
        """Verify that exception InvalidContentType is raised."""
        content_type = 'application/unknown'
        serializer = wsgi.Serializer()

        self.assertRaises(
            exception.InvalidContentType,
            serializer.get_deserialize_handler, content_type)

    def test_serialize_content_type_json(self):
        """Test serialize with content type json."""
        input_data = {'servers': ['test=pass']}
        content_type = 'application/json'
        serializer = wsgi.Serializer()
        result = serializer.serialize(input_data, content_type)

        self.assertEqual(b'{"servers": ["test=pass"]}', result)

    def test_deserialize_raise_bad_request(self):
        """Test serialize verifies that exception is raises."""
        content_type = 'application/unknown'
        data_string = 'test'
        serializer = wsgi.Serializer()

        self.assertRaises(
            webob.exc.HTTPBadRequest,
            serializer.deserialize, data_string, content_type)

    def test_deserialize_json_content_type(self):
        """Test Serializer.deserialize with content type json."""
        content_type = 'application/json'
        data_string = '{"servers": ["test=pass"]}'
        serializer = wsgi.Serializer()
        result = serializer.deserialize(data_string, content_type)

        self.assertEqual({'body': {u'servers': [u'test=pass']}}, result)


class RequestDeserializerTest(testtools.TestCase):
    def setUp(self):
        super(RequestDeserializerTest, self).setUp()

        class JSONDeserializer(object):
            def deserialize(self, data, action='default'):
                return 'pew_json'

        self.body_deserializers = {'application/json': JSONDeserializer()}

        self.deserializer = wsgi.RequestDeserializer(self.body_deserializers)

    def test_get_deserializer(self):
        """Test RequestDeserializer.get_body_deserializer."""
        expected_json_serializer = self.deserializer.get_body_deserializer(
            'application/json')

        self.assertEqual(
            expected_json_serializer,
            self.body_deserializers['application/json'])

    def test_get_expected_content_type(self):
        """Test RequestDeserializer.get_expected_content_type."""
        request = wsgi.Request.blank('/')
        request.headers['Accept'] = 'application/json'

        self.assertEqual('application/json',
                         self.deserializer.get_expected_content_type(request))

    def test_get_action_args(self):
        """Test RequestDeserializer.get_action_args."""
        env = {
            'wsgiorg.routing_args': [None, {
                'controller': None,
                'format': None,
                'action': 'update',
                'id': 12}]}
        expected = {'action': 'update', 'id': 12}

        self.assertEqual(expected,
                         self.deserializer.get_action_args(env))

    def test_deserialize(self):
        """Test RequestDeserializer.deserialize."""
        with mock.patch.object(
                self.deserializer, 'get_action_args') as mock_method:
            mock_method.return_value = {'action': 'create'}
            request = wsgi.Request.blank('/')
            request.headers['Accept'] = 'application/json'
            deserialized = self.deserializer.deserialize(request)
            expected = ('create', {}, 'application/json')

            self.assertEqual(expected, deserialized)

    def test_get_body_deserializer_unknown_content_type(self):
        """Verify that exception InvalidContentType is raised."""
        content_type = 'application/unknown'
        deserializer = wsgi.RequestDeserializer()
        self.assertRaises(
            exception.InvalidContentType,
            deserializer.get_body_deserializer, content_type)


class ResponseSerializerTest(testtools.TestCase):
    def setUp(self):
        super(ResponseSerializerTest, self).setUp()

        class JSONSerializer(object):
            def serialize(self, data, action='default'):
                return b'pew_json'

        class HeadersSerializer(object):
            def serialize(self, response, data, action):
                response.status_int = 404

        self.body_serializers = {'application/json': JSONSerializer()}

        self.serializer = wsgi.ResponseSerializer(
            self.body_serializers, HeadersSerializer())

    def test_serialize_unknown_content_type(self):
        """Verify that exception InvalidContentType is raised."""
        self.assertRaises(
            exception.InvalidContentType,
            self.serializer.serialize,
            {}, 'application/unknown')

    def test_get_body_serializer(self):
        """Verify that exception InvalidContentType is raised."""
        self.assertRaises(
            exception.InvalidContentType,
            self.serializer.get_body_serializer, 'application/unknown')

    def test_get_serializer(self):
        """Test ResponseSerializer.get_body_serializer."""
        content_type = 'application/json'
        self.assertEqual(self.body_serializers[content_type],
                         self.serializer.get_body_serializer(content_type))

    def test_serialize_json_response(self):
        response = self.serializer.serialize({}, 'application/json')

        self.assertEqual('application/json', response.headers['Content-Type'])
        self.assertEqual(b'pew_json', response.body)
        self.assertEqual(404, response.status_int)

    def test_serialize_response_None(self):
        response = self.serializer.serialize(
            None, 'application/json')

        self.assertEqual('application/json', response.headers['Content-Type'])
        self.assertEqual(b'', response.body)
        self.assertEqual(404, response.status_int)


class RequestTest(base.BaseTestCase):

    def test_content_type_missing(self):
        request = wsgi.Request.blank('/tests/123', method='POST')
        request.body = b"<body />"

        self.assertIsNone(request.get_content_type())

    def test_content_type_unsupported(self):
        request = wsgi.Request.blank('/tests/123', method='POST')
        request.headers["Content-Type"] = "text/html"
        request.body = b"fake<br />"

        self.assertIsNone(request.get_content_type())

    def test_content_type_with_charset(self):
        request = wsgi.Request.blank('/tests/123')
        request.headers["Content-Type"] = "application/json; charset=UTF-8"
        result = request.get_content_type()

        self.assertEqual("application/json", result)

    def test_content_type_with_given_content_types(self):
        request = wsgi.Request.blank('/tests/123')
        request.headers["Content-Type"] = "application/new-type;"

        self.assertIsNone(request.get_content_type())

    def test_content_type_from_accept(self):
        request = wsgi.Request.blank('/tests/123')
        request.headers["Accept"] = "application/json"
        result = request.best_match_content_type()

        self.assertEqual("application/json", result)

        request = wsgi.Request.blank('/tests/123')
        request.headers["Accept"] = ("application/json; q=0.3")
        result = request.best_match_content_type()

        self.assertEqual("application/json", result)

    def test_content_type_from_query_extension(self):
        request = wsgi.Request.blank('/tests/123.json')
        result = request.best_match_content_type()

        self.assertEqual("application/json", result)

        request = wsgi.Request.blank('/tests/123.invalid')
        result = request.best_match_content_type()

        self.assertEqual("application/json", result)

    def test_content_type_accept_and_query_extension(self):
        request = wsgi.Request.blank('/tests/123.json')
        request.headers["Accept"] = "application/json"
        result = request.best_match_content_type()

        self.assertEqual("application/json", result)

    def test_content_type_accept_default(self):
        request = wsgi.Request.blank('/tests/123.unsupported')
        request.headers["Accept"] = "application/unsupported1"
        result = request.best_match_content_type()

        self.assertEqual("application/json", result)

    def test_content_type_accept_with_given_content_types(self):
        request = wsgi.Request.blank('/tests/123')
        request.headers["Accept"] = "application/new_type"
        result = request.best_match_content_type()

        self.assertEqual("application/json", result)


class ActionDispatcherTest(base.BaseTestCase):
    def test_dispatch(self):
        """Test ActionDispatcher.dispatch."""
        serializer = wsgi.ActionDispatcher()
        serializer.create = lambda x: x

        self.assertEqual('pants',
                         serializer.dispatch('pants', action='create'))

    def test_dispatch_action_None(self):
        """Test ActionDispatcher.dispatch with none action."""
        serializer = wsgi.ActionDispatcher()
        serializer.create = lambda x: x + ' pants'
        serializer.default = lambda x: x + ' trousers'

        self.assertEqual('Two trousers',
                         serializer.dispatch('Two', action=None))

    def test_dispatch_default(self):
        serializer = wsgi.ActionDispatcher()
        serializer.create = lambda x: x + ' pants'
        serializer.default = lambda x: x + ' trousers'

        self.assertEqual('Two trousers',
                         serializer.dispatch('Two', action='update'))


class ResponseHeadersSerializerTest(base.BaseTestCase):
    def test_default(self):
        serializer = wsgi.ResponseHeaderSerializer()
        response = webob.Response()
        serializer.serialize(response, {'v': '123'}, 'fake')

        self.assertEqual(200, response.status_int)

    def test_custom(self):
        class Serializer(wsgi.ResponseHeaderSerializer):
            def update(self, response, data):
                response.status_int = 404
                response.headers['X-Custom-Header'] = data['v']
        serializer = Serializer()
        response = webob.Response()
        serializer.serialize(response, {'v': '123'}, 'update')

        self.assertEqual(404, response.status_int)
        self.assertEqual('123', response.headers['X-Custom-Header'])


class DictSerializerTest(base.BaseTestCase):

    def test_dispatch_default(self):
        serializer = wsgi.DictSerializer()
        self.assertEqual('',
                         serializer.serialize({}, 'NonExistentAction'))


class JSONDictSerializerTest(base.BaseTestCase):

    def test_json(self):
        input_dict = dict(servers=dict(a=(2, 3)))
        expected_json = b'{"servers":{"a":[2,3]}}'
        serializer = wsgi.JSONDictSerializer()
        result = serializer.serialize(input_dict)
        result = result.replace(b'\n', b'').replace(b' ', b'')

        self.assertEqual(expected_json, result)

    def test_json_with_unicode(self):
        input_dict = dict(servers=dict(a=(2, u'\u7f51\u7edc')))
        expected_json = b'{"servers":{"a":[2,"\\u7f51\\u7edc"]}}'
        serializer = wsgi.JSONDictSerializer()
        result = serializer.serialize(input_dict)
        result = result.replace(b'\n', b'').replace(b' ', b'')

        self.assertEqual(expected_json, result)


class TextDeserializerTest(base.BaseTestCase):

    def test_dispatch_default(self):
        deserializer = wsgi.TextDeserializer()
        self.assertEqual({},
                         deserializer.deserialize({}, 'update'))


class JSONDeserializerTest(base.BaseTestCase):
    def test_json(self):
        data = """{"a": {
                "a1": "1",
                "a2": "2",
                "bs": ["1", "2", "3", {"c": {"c1": "1"}}],
                "d": {"e": "1"},
                "f": "1"}}"""
        as_dict = {
            'body': {
                'a': {
                    'a1': '1',
                    'a2': '2',
                    'bs': ['1', '2', '3', {'c': {'c1': '1'}}],
                    'd': {'e': '1'},
                    'f': '1'}}}
        deserializer = wsgi.JSONDeserializer()
        self.assertEqual(as_dict,
                         deserializer.deserialize(data))

    def test_default_raise_Malformed_Exception(self):
        """Test JsonDeserializer.default.

        Test verifies JsonDeserializer.default raises exception
        MalformedRequestBody correctly.
        """
        data_string = ""
        deserializer = wsgi.JSONDeserializer()

        self.assertRaises(
            exception.MalformedRequestBody,
            deserializer.default, data_string)

    def test_json_with_utf8(self):
        data = b'{"a": "\xe7\xbd\x91\xe7\xbb\x9c"}'
        as_dict = {'body': {'a': u'\u7f51\u7edc'}}
        deserializer = wsgi.JSONDeserializer()
        self.assertEqual(as_dict,
                         deserializer.deserialize(data))

    def test_json_with_unicode(self):
        data = b'{"a": "\u7f51\u7edc"}'
        as_dict = {'body': {'a': u'\u7f51\u7edc'}}
        deserializer = wsgi.JSONDeserializer()
        self.assertEqual(as_dict,
                         deserializer.deserialize(data))


class RequestHeadersDeserializerTest(base.BaseTestCase):

    def test_default(self):
        deserializer = wsgi.RequestHeadersDeserializer()
        req = wsgi.Request.blank('/')

        self.assertEqual({},
                         deserializer.deserialize(req, 'nonExistent'))

    def test_custom(self):
        class Deserializer(wsgi.RequestHeadersDeserializer):
            def update(self, request):
                return {'a': request.headers['X-Custom-Header']}
        deserializer = Deserializer()
        req = wsgi.Request.blank('/')
        req.headers['X-Custom-Header'] = 'b'
        self.assertEqual({'a': 'b'},
                         deserializer.deserialize(req, 'update'))


class ResourceTest(base.BaseTestCase):

    @staticmethod
    def my_fault_body_function():
        return 'off'

    class Controller(object):
        def index(self, request, index=None):
            return index

    def test_dispatch(self):
        resource = wsgi.Resource(self.Controller(),
                                 self.my_fault_body_function)
        actual = resource.dispatch(
            resource.controller, 'index', action_args={'index': 'off'})
        expected = 'off'

        self.assertEqual(expected, actual)

    def test_dispatch_unknown_controller_action(self):
        resource = wsgi.Resource(self.Controller(),
                                 self.my_fault_body_function)
        self.assertRaises(
            AttributeError, resource.dispatch,
            resource.controller, 'create', {})

    def test_malformed_request_body_throws_bad_request(self):
        resource = wsgi.Resource(None, self.my_fault_body_function)
        request = wsgi.Request.blank(
            "/", body=b"{mal:formed", method='POST',
            headers={'Content-Type': "application/json"})

        response = resource(request)
        self.assertEqual(400, response.status_int)

    def test_wrong_content_type_throws_unsupported_media_type_error(self):
        resource = wsgi.Resource(None, self.my_fault_body_function)
        request = wsgi.Request.blank(
            "/", body=b"{some:json}", method='POST',
            headers={'Content-Type': "xxx"})

        response = resource(request)
        self.assertEqual(400, response.status_int)

    def test_wrong_content_type_server_error(self):
        resource = wsgi.Resource(None, self.my_fault_body_function)
        request = wsgi.Request.blank(
            "/", method='POST', headers={'Content-Type': "unknow"})

        response = resource(request)
        self.assertEqual(500, response.status_int)

    def test_call_resource_class_bad_request(self):
        class FakeRequest(object):
            def __init__(self):
                self.url = 'http://where.no'
                self.environ = 'environ'
                self.body = 'body'

            def method(self):
                pass

            def best_match_content_type(self):
                return 'best_match_content_type'

        resource = wsgi.Resource(self.Controller(),
                                 self.my_fault_body_function)
        request = FakeRequest()
        result = resource(request)
        self.assertEqual(400, result.status_int)

    def test_type_error(self):
        resource = wsgi.Resource(self.Controller(),
                                 self.my_fault_body_function)
        request = wsgi.Request.blank(
            "/", method='POST', headers={'Content-Type': "json"})

        response = resource.dispatch(
            request, action='index', action_args='test')
        self.assertEqual(400, response.status_int)

    def test_call_resource_class_internal_error(self):
        class FakeRequest(object):
            def __init__(self):
                self.url = 'http://where.no'
                self.environ = 'environ'
                self.body = '{"Content-Type": "json"}'

            def method(self):
                pass

            def best_match_content_type(self):
                return 'application/json'

        resource = wsgi.Resource(self.Controller(),
                                 self.my_fault_body_function)
        request = FakeRequest()
        result = resource(request)
        self.assertEqual(500, result.status_int)


class FaultTest(base.BaseTestCase):
    def test_call_fault(self):
        class MyException(object):
            status_int = 415
            explanation = 'test'

        my_exceptions = MyException()
        my_fault = wsgi.Fault(exception=my_exceptions)
        request = wsgi.Request.blank(
            "/", method='POST', headers={'Content-Type': "unknow"})
        response = my_fault(request)
        self.assertEqual(415, response.status_int)
