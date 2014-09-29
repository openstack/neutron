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
import urllib2

import mock
from oslo.config import cfg
import testtools
import webob
import webob.exc

from neutron.api.v2 import attributes
from neutron.common import constants
from neutron.common import exceptions as exception
from neutron.tests import base
from neutron import wsgi

CONF = cfg.CONF

TEST_VAR_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__),
                               '..', 'var'))


def open_no_proxy(*args, **kwargs):
    opener = urllib2.build_opener(urllib2.ProxyHandler({}))
    return opener.open(*args, **kwargs)


class TestWSGIServer(base.BaseTestCase):
    """WSGI server tests."""

    def test_start_random_port(self):
        server = wsgi.Server("test_random_port")
        server.start(None, 0, host="127.0.0.1")
        self.assertNotEqual(0, server.port)
        server.stop()
        server.wait()

    @mock.patch('neutron.openstack.common.service.ProcessLauncher')
    def test_start_multiple_workers(self, ProcessLauncher):
        launcher = ProcessLauncher.return_value

        server = wsgi.Server("test_multiple_processes")
        server.start(None, 0, host="127.0.0.1", workers=2)
        launcher.launch_service.assert_called_once_with(mock.ANY, workers=2)

        server.stop()
        launcher.stop.assert_called_once_with()

        server.wait()
        launcher.wait.assert_called_once_with()

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
                            mock_listen.return_value)
                    ])

    def test_app(self):
        greetings = 'Hello, World!!!'

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
        serializer = wsgi.Serializer(default_xmlns="fake")
        result = serializer.serialize(input_data, content_type)

        self.assertEqual('{"servers": ["test=pass"]}', result)

    def test_serialize_content_type_xml(self):
        """Test serialize with content type xml."""
        input_data = {'servers': ['test=pass']}
        content_type = 'application/xml'
        serializer = wsgi.Serializer(default_xmlns="fake")
        result = serializer.serialize(input_data, content_type)
        expected = (
            '<?xml version=\'1.0\''
            ' encoding=\'UTF-8\'?>\n'
            '<servers xmlns="http://openstack.org/quantum/api/v2.0" '
            'xmlns:quantum="http://openstack.org/quantum/api/v2.0" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            '<server>test=pass</server></servers>'
        )

        self.assertEqual(expected, result)

    def test_deserialize_raise_bad_request(self):
        """Test serialize verifies that exception is raises."""
        content_type = 'application/unknown'
        data_string = 'test'
        serializer = wsgi.Serializer(default_xmlns="fake")

        self.assertRaises(
            webob.exc.HTTPBadRequest,
            serializer.deserialize, data_string, content_type)

    def test_deserialize_json_content_type(self):
        """Test Serializer.deserialize with content type json."""
        content_type = 'application/json'
        data_string = '{"servers": ["test=pass"]}'
        serializer = wsgi.Serializer(default_xmlns="fake")
        result = serializer.deserialize(data_string, content_type)

        self.assertEqual({'body': {u'servers': [u'test=pass']}}, result)

    def test_deserialize_xml_content_type(self):
        """Test deserialize with content type xml."""
        content_type = 'application/xml'
        data_string = (
            '<servers xmlns="fake">'
            '<server>test=pass</server>'
            '</servers>'
        )
        serializer = wsgi.Serializer(
            default_xmlns="fake", metadata={'xmlns': 'fake'})
        result = serializer.deserialize(data_string, content_type)
        expected = {'body': {'servers': {'server': 'test=pass'}}}

        self.assertEqual(expected, result)

    def test_deserialize_xml_content_type_with_meta(self):
        """Test deserialize with content type xml with meta."""
        content_type = 'application/xml'
        data_string = (
            '<servers>'
            '<server name="s1">'
            '<test test="a">passed</test>'
            '</server>'
            '</servers>'
        )

        metadata = {'plurals': {'servers': 'server'}, 'xmlns': 'fake'}
        serializer = wsgi.Serializer(
            default_xmlns="fake", metadata=metadata)
        result = serializer.deserialize(data_string, content_type)
        expected = {'body': {'servers': [{'name': 's1', 'test': 'passed'}]}}

        self.assertEqual(expected, result)

    def test_serialize_xml_root_key_is_dict(self):
        """Test Serializer.serialize with content type xml with meta dict."""
        content_type = 'application/xml'
        data = {'servers': {'network': (2, 3)}}
        metadata = {'xmlns': 'fake'}

        serializer = wsgi.Serializer(default_xmlns="fake", metadata=metadata)
        result = serializer.serialize(data, content_type)
        result = result.replace('\n', '')
        expected = (
            '<?xml version=\'1.0\' encoding=\'UTF-8\'?>'
            '<servers xmlns="fake" xmlns:quantum="fake" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            '<network>(2, 3)</network></servers>'
        )

        self.assertEqual(result, expected)

    def test_serialize_xml_root_key_is_list(self):
        """Test serialize with content type xml with meta list."""
        input_dict = {'servers': ['test=pass']}
        content_type = 'application/xml'
        metadata = {'application/xml': {
                    'xmlns': 'fake'}}
        serializer = wsgi.Serializer(default_xmlns="fake", metadata=metadata)
        result = serializer.serialize(input_dict, content_type)
        result = result.replace('\n', '').replace(' ', '')
        expected = (
            '<?xmlversion=\'1.0\''
            'encoding=\'UTF-8\'?>'
            '<serversxmlns="http://openstack.org/quantum/api/v2.0"'
            'xmlns:quantum="http://openstack.org/quantum/api/v2.0"'
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            '<server>test=pass</server></servers>'
        )

        self.assertEqual(result, expected)

    def test_serialize_xml_root_is_None(self):
        input_dict = {'test': 'pass'}
        content_type = 'application/xml'
        serializer = wsgi.Serializer(default_xmlns="fake")
        result = serializer.serialize(input_dict, content_type)
        result = result.replace('\n', '').replace(' ', '')
        expected = (
            '<?xmlversion=\'1.0\''
            'encoding=\'UTF-8\'?>'
            '<testxmlns="http://openstack.org/quantum/api/v2.0"'
            'xmlns:quantum="http://openstack.org/quantum/api/v2.0"'
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            'pass</test>'
        )

        self.assertEqual(result, expected)


class RequestDeserializerTest(testtools.TestCase):
    def setUp(self):
        super(RequestDeserializerTest, self).setUp()

        class JSONDeserializer(object):
            def deserialize(self, data, action='default'):
                return 'pew_json'

        class XMLDeserializer(object):
            def deserialize(self, data, action='default'):
                return 'pew_xml'

        self.body_deserializers = {
            'application/json': JSONDeserializer(),
            'application/xml': XMLDeserializer()}

        self.deserializer = wsgi.RequestDeserializer(self.body_deserializers)

    def test_get_deserializer(self):
        """Test RequestDeserializer.get_body_deserializer."""
        expected_json_serializer = self.deserializer.get_body_deserializer(
            'application/json')
        expected_xml_serializer = self.deserializer.get_body_deserializer(
            'application/xml')

        self.assertEqual(
            expected_json_serializer,
            self.body_deserializers['application/json'])
        self.assertEqual(
            expected_xml_serializer,
            self.body_deserializers['application/xml'])

    def test_get_expected_content_type(self):
        """Test RequestDeserializer.get_expected_content_type."""
        request = wsgi.Request.blank('/')
        request.headers['Accept'] = 'application/json'

        self.assertEqual(
            self.deserializer.get_expected_content_type(request),
            'application/json')

    def test_get_action_args(self):
        """Test RequestDeserializer.get_action_args."""
        env = {
            'wsgiorg.routing_args': [None, {
                'controller': None,
                'format': None,
                'action': 'update',
                'id': 12}]}
        expected = {'action': 'update', 'id': 12}

        self.assertEqual(
            self.deserializer.get_action_args(env), expected)

    def test_deserialize(self):
        """Test RequestDeserializer.deserialize."""
        with mock.patch.object(
            self.deserializer, 'get_action_args') as mock_method:
            mock_method.return_value = {'action': 'create'}
            request = wsgi.Request.blank('/')
            request.headers['Accept'] = 'application/xml'
            deserialized = self.deserializer.deserialize(request)
            expected = ('create', {}, 'application/xml')

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
                return 'pew_json'

        class XMLSerializer(object):
            def serialize(self, data, action='default'):
                return 'pew_xml'

        class HeadersSerializer(object):
            def serialize(self, response, data, action):
                response.status_int = 404

        self.body_serializers = {
            'application/json': JSONSerializer(),
            'application/xml': XMLSerializer()}

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
        self.assertEqual(
            self.serializer.get_body_serializer(content_type),
            self.body_serializers[content_type])

    def test_serialize_json_response(self):
        response = self.serializer.serialize({}, 'application/json')

        self.assertEqual(response.headers['Content-Type'], 'application/json')
        self.assertEqual(response.body, 'pew_json')
        self.assertEqual(response.status_int, 404)

    def test_serialize_xml_response(self):
        response = self.serializer.serialize({}, 'application/xml')

        self.assertEqual(response.headers['Content-Type'], 'application/xml')
        self.assertEqual(response.body, 'pew_xml')
        self.assertEqual(response.status_int, 404)

    def test_serialize_response_None(self):
        response = self.serializer.serialize(
            None, 'application/json')

        self.assertEqual(response.headers['Content-Type'], 'application/json')
        self.assertEqual(response.body, '')
        self.assertEqual(response.status_int, 404)


class RequestTest(base.BaseTestCase):

    def test_content_type_missing(self):
        request = wsgi.Request.blank('/tests/123', method='POST')
        request.body = "<body />"

        self.assertIsNone(request.get_content_type())

    def test_content_type_unsupported(self):
        request = wsgi.Request.blank('/tests/123', method='POST')
        request.headers["Content-Type"] = "text/html"
        request.body = "fake<br />"

        self.assertIsNone(request.get_content_type())

    def test_content_type_with_charset(self):
        request = wsgi.Request.blank('/tests/123')
        request.headers["Content-Type"] = "application/json; charset=UTF-8"
        result = request.get_content_type()

        self.assertEqual(result, "application/json")

    def test_content_type_with_given_content_types(self):
        request = wsgi.Request.blank('/tests/123')
        request.headers["Content-Type"] = "application/new-type;"

        self.assertIsNone(request.get_content_type())

    def test_content_type_from_accept(self):
        request = wsgi.Request.blank('/tests/123')
        request.headers["Accept"] = "application/xml"
        result = request.best_match_content_type()

        self.assertEqual(result, "application/xml")

        request = wsgi.Request.blank('/tests/123')
        request.headers["Accept"] = "application/json"
        result = request.best_match_content_type()

        self.assertEqual(result, "application/json")

        request = wsgi.Request.blank('/tests/123')
        request.headers["Accept"] = "application/xml, application/json"
        result = request.best_match_content_type()

        self.assertEqual(result, "application/json")

        request = wsgi.Request.blank('/tests/123')
        request.headers["Accept"] = ("application/json; q=0.3, "
                                     "application/xml; q=0.9")
        result = request.best_match_content_type()

        self.assertEqual(result, "application/xml")

    def test_content_type_from_query_extension(self):
        request = wsgi.Request.blank('/tests/123.xml')
        result = request.best_match_content_type()

        self.assertEqual(result, "application/xml")

        request = wsgi.Request.blank('/tests/123.json')
        result = request.best_match_content_type()

        self.assertEqual(result, "application/json")

        request = wsgi.Request.blank('/tests/123.invalid')
        result = request.best_match_content_type()

        self.assertEqual(result, "application/json")

    def test_content_type_accept_and_query_extension(self):
        request = wsgi.Request.blank('/tests/123.xml')
        request.headers["Accept"] = "application/json"
        result = request.best_match_content_type()

        self.assertEqual(result, "application/xml")

    def test_content_type_accept_default(self):
        request = wsgi.Request.blank('/tests/123.unsupported')
        request.headers["Accept"] = "application/unsupported1"
        result = request.best_match_content_type()

        self.assertEqual(result, "application/json")

    def test_content_type_accept_with_given_content_types(self):
        request = wsgi.Request.blank('/tests/123')
        request.headers["Accept"] = "application/new_type"
        result = request.best_match_content_type()

        self.assertEqual(result, 'application/json')


class ActionDispatcherTest(base.BaseTestCase):
    def test_dispatch(self):
        """Test ActionDispatcher.dispatch."""
        serializer = wsgi.ActionDispatcher()
        serializer.create = lambda x: x

        self.assertEqual(
            serializer.dispatch('pants', action='create'),
            'pants')

    def test_dispatch_action_None(self):
        """Test ActionDispatcher.dispatch with none action."""
        serializer = wsgi.ActionDispatcher()
        serializer.create = lambda x: x + ' pants'
        serializer.default = lambda x: x + ' trousers'

        self.assertEqual(
            serializer.dispatch('Two', action=None),
            'Two trousers')

    def test_dispatch_default(self):
        serializer = wsgi.ActionDispatcher()
        serializer.create = lambda x: x + ' pants'
        serializer.default = lambda x: x + ' trousers'

        self.assertEqual(
            serializer.dispatch('Two', action='update'),
            'Two trousers')


class ResponseHeadersSerializerTest(base.BaseTestCase):
    def test_default(self):
        serializer = wsgi.ResponseHeaderSerializer()
        response = webob.Response()
        serializer.serialize(response, {'v': '123'}, 'fake')

        self.assertEqual(response.status_int, 200)

    def test_custom(self):
        class Serializer(wsgi.ResponseHeaderSerializer):
            def update(self, response, data):
                response.status_int = 404
                response.headers['X-Custom-Header'] = data['v']
        serializer = Serializer()
        response = webob.Response()
        serializer.serialize(response, {'v': '123'}, 'update')

        self.assertEqual(response.status_int, 404)
        self.assertEqual(response.headers['X-Custom-Header'], '123')


class DictSerializerTest(base.BaseTestCase):

    def test_dispatch_default(self):
        serializer = wsgi.DictSerializer()
        self.assertEqual(
            serializer.serialize({}, 'NonExistentAction'), '')


class JSONDictSerializerTest(base.BaseTestCase):

    def test_json(self):
        input_dict = dict(servers=dict(a=(2, 3)))
        expected_json = '{"servers":{"a":[2,3]}}'
        serializer = wsgi.JSONDictSerializer()
        result = serializer.serialize(input_dict)
        result = result.replace('\n', '').replace(' ', '')

        self.assertEqual(result, expected_json)

    def test_json_with_utf8(self):
        input_dict = dict(servers=dict(a=(2, '\xe7\xbd\x91\xe7\xbb\x9c')))
        expected_json = '{"servers":{"a":[2,"\\u7f51\\u7edc"]}}'
        serializer = wsgi.JSONDictSerializer()
        result = serializer.serialize(input_dict)
        result = result.replace('\n', '').replace(' ', '')

        self.assertEqual(result, expected_json)

    def test_json_with_unicode(self):
        input_dict = dict(servers=dict(a=(2, u'\u7f51\u7edc')))
        expected_json = '{"servers":{"a":[2,"\\u7f51\\u7edc"]}}'
        serializer = wsgi.JSONDictSerializer()
        result = serializer.serialize(input_dict)
        result = result.replace('\n', '').replace(' ', '')

        self.assertEqual(result, expected_json)


class TextDeserializerTest(base.BaseTestCase):

    def test_dispatch_default(self):
        deserializer = wsgi.TextDeserializer()
        self.assertEqual(
            deserializer.deserialize({}, 'update'), {})


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
        self.assertEqual(
            deserializer.deserialize(data), as_dict)

    def test_default_raise_Malformed_Exception(self):
        """Test JsonDeserializer.default.

        Test verifies JsonDeserializer.default raises exception
        MalformedRequestBody correctly.
        """
        data_string = ""
        deserializer = wsgi.JSONDeserializer()

        self.assertRaises(
            exception.MalformedRequestBody, deserializer.default, data_string)

    def test_json_with_utf8(self):
        data = '{"a": "\xe7\xbd\x91\xe7\xbb\x9c"}'
        as_dict = {'body': {'a': u'\u7f51\u7edc'}}
        deserializer = wsgi.JSONDeserializer()
        self.assertEqual(
            deserializer.deserialize(data), as_dict)

    def test_json_with_unicode(self):
        data = '{"a": "\u7f51\u7edc"}'
        as_dict = {'body': {'a': u'\u7f51\u7edc'}}
        deserializer = wsgi.JSONDeserializer()
        self.assertEqual(
            deserializer.deserialize(data), as_dict)


class XMLDeserializerTest(base.BaseTestCase):
    def test_xml_empty(self):
        xml = '<a></a>'
        as_dict = {'body': {'a': ''}}
        deserializer = wsgi.XMLDeserializer()

        self.assertEqual(
            deserializer.deserialize(xml), as_dict)

    def test_initialization(self):
        xml = '<a><b>test</b></a>'
        deserializer = wsgi.XMLDeserializer()

        self.assertEqual(
            {'body': {u'a': {u'b': u'test'}}}, deserializer(xml))

    def test_default_raise_Malformed_Exception(self):
        """Verify that exception MalformedRequestBody is raised."""
        data_string = ""
        deserializer = wsgi.XMLDeserializer()

        self.assertRaises(
            exception.MalformedRequestBody, deserializer.default, data_string)

    def test_xml_with_utf8(self):
        xml = '<a>\xe7\xbd\x91\xe7\xbb\x9c</a>'
        as_dict = {'body': {'a': u'\u7f51\u7edc'}}
        deserializer = wsgi.XMLDeserializer()

        self.assertEqual(
            deserializer.deserialize(xml), as_dict)


class RequestHeadersDeserializerTest(base.BaseTestCase):

    def test_default(self):
        deserializer = wsgi.RequestHeadersDeserializer()
        req = wsgi.Request.blank('/')

        self.assertEqual(
            deserializer.deserialize(req, 'nonExistent'), {})

    def test_custom(self):
        class Deserializer(wsgi.RequestHeadersDeserializer):
            def update(self, request):
                return {'a': request.headers['X-Custom-Header']}
        deserializer = Deserializer()
        req = wsgi.Request.blank('/')
        req.headers['X-Custom-Header'] = 'b'
        self.assertEqual(
            deserializer.deserialize(req, 'update'), {'a': 'b'})


class ResourceTest(base.BaseTestCase):
    def test_dispatch(self):
        class Controller(object):
            def index(self, request, index=None):
                return index

        def my_fault_body_function():
            return 'off'

        resource = wsgi.Resource(Controller(), my_fault_body_function)
        actual = resource.dispatch(
            resource.controller, 'index', action_args={'index': 'off'})
        expected = 'off'

        self.assertEqual(actual, expected)

    def test_dispatch_unknown_controller_action(self):
        class Controller(object):
            def index(self, request, pants=None):
                return pants

        def my_fault_body_function():
            return 'off'

        resource = wsgi.Resource(Controller(), my_fault_body_function)
        self.assertRaises(
            AttributeError, resource.dispatch,
            resource.controller, 'create', {})

    def test_malformed_request_body_throws_bad_request(self):
        def my_fault_body_function():
            return 'off'

        resource = wsgi.Resource(None, my_fault_body_function)
        request = wsgi.Request.blank(
            "/", body="{mal:formed", method='POST',
            headers={'Content-Type': "application/json"})

        response = resource(request)
        self.assertEqual(response.status_int, 400)

    def test_wrong_content_type_throws_unsupported_media_type_error(self):
        def my_fault_body_function():
            return 'off'
        resource = wsgi.Resource(None, my_fault_body_function)
        request = wsgi.Request.blank(
            "/", body="{some:json}", method='POST',
            headers={'Content-Type': "xxx"})

        response = resource(request)
        self.assertEqual(response.status_int, 400)

    def test_wrong_content_type_server_error(self):
        def my_fault_body_function():
            return 'off'
        resource = wsgi.Resource(None, my_fault_body_function)
        request = wsgi.Request.blank(
            "/", method='POST', headers={'Content-Type': "unknow"})

        response = resource(request)
        self.assertEqual(response.status_int, 500)

    def test_call_resource_class_bad_request(self):
        class Controller(object):
            def index(self, request, index=None):
                return index

        def my_fault_body_function():
            return 'off'

        class FakeRequest():
            def __init__(self):
                self.url = 'http://where.no'
                self.environ = 'environ'
                self.body = 'body'

            def method(self):
                pass

            def best_match_content_type(self):
                return 'best_match_content_type'

        resource = wsgi.Resource(Controller(), my_fault_body_function)
        request = FakeRequest()
        result = resource(request)
        self.assertEqual(400, result.status_int)

    def test_type_error(self):
        class Controller(object):
            def index(self, request, index=None):
                return index

        def my_fault_body_function():
            return 'off'
        resource = wsgi.Resource(Controller(), my_fault_body_function)
        request = wsgi.Request.blank(
            "/", method='POST', headers={'Content-Type': "xml"})

        response = resource.dispatch(
            request, action='index', action_args='test')
        self.assertEqual(400, response.status_int)

    def test_call_resource_class_internal_error(self):
        class Controller(object):
            def index(self, request, index=None):
                return index

        def my_fault_body_function():
            return 'off'

        class FakeRequest():
            def __init__(self):
                self.url = 'http://where.no'
                self.environ = 'environ'
                self.body = '{"Content-Type": "xml"}'

            def method(self):
                pass

            def best_match_content_type(self):
                return 'application/json'

        resource = wsgi.Resource(Controller(), my_fault_body_function)
        request = FakeRequest()
        result = resource(request)
        self.assertEqual(500, result.status_int)


class MiddlewareTest(base.BaseTestCase):
    def test_process_response(self):
        def application(environ, start_response):
            response = 'Success'
            return response
        response = application('test', 'fake')
        result = wsgi.Middleware(application).process_response(response)
        self.assertEqual('Success', result)


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


class XMLDictSerializerTest(base.BaseTestCase):
    def test_xml(self):
        NETWORK = {'network': {'test': None,
                               'tenant_id': 'test-tenant',
                               'name': 'net1',
                               'admin_state_up': True,
                               'subnets': [],
                               'dict': {},
                               'int': 3,
                               'long': 4L,
                               'float': 5.0,
                               'prefix:external': True,
                               'tests': [{'test1': 'value1'},
                                         {'test2': 2, 'test3': 3}]}}
        # XML is:
        # <network xmlns="http://openstack.org/quantum/api/v2.0"
        #    xmlns:prefix="http://xxxx.yy.com"
        #    xmlns:quantum="http://openstack.org/quantum/api/v2.0"
        #    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        #    <subnets quantum:type="list" />  # Empty List
        #    <int quantum:type="int">3</int>  # Integer text
        #    <int quantum:type="long">4</int>  # Long text
        #    <int quantum:type="float">5.0</int>  # Float text
        #    <dict quantum:type="dict" />     # Empty Dict
        #    <name>net1</name>
        #    <admin_state_up quantum:type="bool">True</admin_state_up> # Bool
        #    <test xsi:nil="true" />          # None
        #    <tenant_id>test-tenant</tenant_id>
        #    # We must have a namespace defined in root for prefix:external
        #    <prefix:external quantum:type="bool">True</prefix:external>
        #    <tests>                          # List
        #       <test><test1>value1</test1></test>
        #       <test><test3 quantum:type="int">3</test3>
        #             <test2 quantum:type="int">2</test2>
        #       </test></tests>
        # </network>

        metadata = attributes.get_attr_metadata()
        ns = {'prefix': 'http://xxxx.yy.com'}
        metadata[constants.EXT_NS] = ns
        metadata['plurals'] = {'tests': 'test'}
        serializer = wsgi.XMLDictSerializer(metadata)
        result = serializer.serialize(NETWORK)
        deserializer = wsgi.XMLDeserializer(metadata)
        new_net = deserializer.deserialize(result)['body']
        self.assertEqual(NETWORK, new_net)

    def test_None(self):
        data = None
        # Since it is None, we use xsi:nil='true'.
        # In addition, we use an
        # virtual XML root _v_root to wrap the XML doc.
        # XML is:
        # <_v_root xsi:nil="true"
        #          xmlns="http://openstack.org/quantum/api/v2.0"
        #          xmlns:quantum="http://openstack.org/quantum/api/v2.0"
        #          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" />
        serializer = wsgi.XMLDictSerializer(attributes.get_attr_metadata())
        result = serializer.serialize(data)
        deserializer = wsgi.XMLDeserializer(attributes.get_attr_metadata())
        new_data = deserializer.deserialize(result)['body']
        self.assertIsNone(new_data)

    def test_empty_dic_xml(self):
        data = {}
        # Since it is an empty dict, we use quantum:type='dict' and
        # an empty XML element to represent it. In addition, we use an
        # virtual XML root _v_root to wrap the XML doc.
        # XML is:
        # <_v_root quantum:type="dict"
        #          xmlns="http://openstack.org/quantum/api/v2.0"
        #          xmlns:quantum="http://openstack.org/quantum/api/v2.0"
        #          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" />
        serializer = wsgi.XMLDictSerializer(attributes.get_attr_metadata())
        result = serializer.serialize(data)
        deserializer = wsgi.XMLDeserializer(attributes.get_attr_metadata())
        new_data = deserializer.deserialize(result)['body']
        self.assertEqual(data, new_data)

    def test_non_root_one_item_dic_xml(self):
        data = {'test1': 1}
        # We have a key in this dict, and its value is an integer.
        # XML is:
        # <test1 quantum:type="int"
        #        xmlns="http://openstack.org/quantum/api/v2.0"
        #        xmlns:quantum="http://openstack.org/quantum/api/v2.0"
        #        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        # 1</test1>

        serializer = wsgi.XMLDictSerializer(attributes.get_attr_metadata())
        result = serializer.serialize(data)
        deserializer = wsgi.XMLDeserializer(attributes.get_attr_metadata())
        new_data = deserializer.deserialize(result)['body']
        self.assertEqual(data, new_data)

    def test_non_root_two_items_dic_xml(self):
        data = {'test1': 1, 'test2': '2'}
        # We have no root element in this data, We will use a virtual
        # root element _v_root to wrap the doct.
        # The XML is:
        # <_v_root xmlns="http://openstack.org/quantum/api/v2.0"
        #          xmlns:quantum="http://openstack.org/quantum/api/v2.0"
        #          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        #    <test1 quantum:type="int">1</test1><test2>2</test2>
        # </_v_root>

        serializer = wsgi.XMLDictSerializer(attributes.get_attr_metadata())
        result = serializer.serialize(data)
        deserializer = wsgi.XMLDeserializer(attributes.get_attr_metadata())
        new_data = deserializer.deserialize(result)['body']
        self.assertEqual(data, new_data)

    def test_xml_root_key_is_list(self):
        input_dict = {'servers': ['test-pass']}
        serializer = wsgi.XMLDictSerializer(xmlns="fake")
        result = serializer.default(input_dict)
        result = result.replace('\n', '').replace(' ', '')
        expected = (
            '<?xmlversion=\'1.0\'encoding=\'UTF-8\'?>'
            '<serversxmlns="fake"xmlns:quantum="fake"'
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            '<server>test-pass</server></servers>'
        )

        self.assertEqual(result, expected)

    def test_xml_meta_contains_node_name_list(self):
        input_dict = {'servers': ['test-pass']}
        servers = {'nodename': 'test',
                   'item_name': 'test',
                   'item_key': 'test'}
        metadata = {'list_collections': {'servers': servers}}
        serializer = wsgi.XMLDictSerializer(xmlns="fake", metadata=metadata)
        result = serializer.default(input_dict)
        result = result.replace('\n', '').replace(' ', '')
        expected = (
            '<?xmlversion=\'1.0\'encoding=\'UTF-8\'?>'
            '<serversxmlns="fake"xmlns:quantum="fake"'
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            '<server>test-pass</server></servers>'
        )

        self.assertEqual(result, expected)

    def test_xml_meta_contains_node_name_dict(self):
        input_dict = {'servers': {'a': {'2': '3'}}}
        servers = {'servers': {
            'nodename': 'test',
            'item_name': 'test',
            'item_key': 'test'}}
        metadata = {'dict_collections': servers}
        serializer = wsgi.XMLDictSerializer(xmlns="fake", metadata=metadata)
        result = serializer.default(input_dict)
        result = result.replace('\n', '').replace(' ', '')
        expected = (
            '<?xmlversion=\'1.0\'encoding=\'UTF-8\'?>'
            '<serversxmlns="fake"xmlns:quantum="fake"'
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            '<a><2>3</2></a></servers>'
        )

        self.assertEqual(result, expected)

    def test_call(self):
        data = {'servers': {'a': {'2': '3'}}}
        serializer = wsgi.XMLDictSerializer()
        expected = (
            '<?xmlversion=\'1.0\'encoding=\'UTF-8\'?>'
            '<serversxmlns="http://openstack.org/quantum/api/v2.0"'
            'xmlns:quantum="http://openstack.org/quantum/api/v2.0"'
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            '<a><2>3</2></a></servers>'
        )
        result = serializer(data)
        result = result.replace('\n', '').replace(' ', '')
        self.assertEqual(expected, result)

    def test_xml_with_utf8(self):
        data = {'servers': '\xe7\xbd\x91\xe7\xbb\x9c'}
        serializer = wsgi.XMLDictSerializer()
        expected = (
            '<?xmlversion=\'1.0\'encoding=\'UTF-8\'?>'
            '<serversxmlns="http://openstack.org/quantum/api/v2.0"'
            'xmlns:quantum="http://openstack.org/quantum/api/v2.0"'
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            '\xe7\xbd\x91\xe7\xbb\x9c</servers>'
        )
        result = serializer(data)
        result = result.replace('\n', '').replace(' ', '')
        self.assertEqual(expected, result)

    def test_xml_with_unicode(self):
        data = {'servers': u'\u7f51\u7edc'}
        serializer = wsgi.XMLDictSerializer()
        expected = (
            '<?xmlversion=\'1.0\'encoding=\'UTF-8\'?>'
            '<serversxmlns="http://openstack.org/quantum/api/v2.0"'
            'xmlns:quantum="http://openstack.org/quantum/api/v2.0"'
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            '\xe7\xbd\x91\xe7\xbb\x9c</servers>'
        )
        result = serializer(data)
        result = result.replace('\n', '').replace(' ', '')
        self.assertEqual(expected, result)


class TestWSGIServerWithSSL(base.BaseTestCase):
    """WSGI server tests."""

    def test_app_using_ssl(self):
        CONF.set_default('use_ssl', True)
        CONF.set_default("ssl_cert_file",
                         os.path.join(TEST_VAR_DIR, 'certificate.crt'))
        CONF.set_default("ssl_key_file",
                         os.path.join(TEST_VAR_DIR, 'privatekey.key'))

        greetings = 'Hello, World!!!'

        @webob.dec.wsgify
        def hello_world(req):
            return greetings

        server = wsgi.Server("test_app")
        server.start(hello_world, 0, host="127.0.0.1")

        response = open_no_proxy('https://127.0.0.1:%d/' % server.port)

        self.assertEqual(greetings, response.read())

        server.stop()

    def test_app_using_ssl_combined_cert_and_key(self):
        CONF.set_default('use_ssl', True)
        CONF.set_default("ssl_cert_file",
                         os.path.join(TEST_VAR_DIR, 'certandkey.pem'))

        greetings = 'Hello, World!!!'

        @webob.dec.wsgify
        def hello_world(req):
            return greetings

        server = wsgi.Server("test_app")
        server.start(hello_world, 0, host="127.0.0.1")

        response = open_no_proxy('https://127.0.0.1:%d/' % server.port)

        self.assertEqual(greetings, response.read())

        server.stop()

    def test_app_using_ipv6_and_ssl(self):
        CONF.set_default('use_ssl', True)
        CONF.set_default("ssl_cert_file",
                         os.path.join(TEST_VAR_DIR, 'certificate.crt'))
        CONF.set_default("ssl_key_file",
                         os.path.join(TEST_VAR_DIR, 'privatekey.key'))

        greetings = 'Hello, World!!!'

        @webob.dec.wsgify
        def hello_world(req):
            return greetings

        server = wsgi.Server("test_app")
        server.start(hello_world, 0, host="::1")

        response = open_no_proxy('https://[::1]:%d/' % server.port)

        self.assertEqual(greetings, response.read())

        server.stop()
