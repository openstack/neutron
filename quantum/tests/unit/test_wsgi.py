# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack LLC.
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

import socket

import mock
import testtools

from quantum.api.v2 import attributes
from quantum.common import constants
from quantum.common import exceptions as exception
from quantum import wsgi


class TestWSGIServer(testtools.TestCase):
    """WSGI server tests."""

    def test_start_random_port(self):
        server = wsgi.Server("test_random_port")
        server.start(None, 0, host="127.0.0.1")
        self.assertNotEqual(0, server.port)
        server.stop()
        server.wait()

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
                        backlog=128
                    )

                    mock_pool.spawn.assert_has_calls([
                        mock.call(
                            server._run,
                            None,
                            mock_listen.return_value)
                    ])


class SerializerTest(testtools.TestCase):
    def test_serialize_unknown_content_type(self):
        """
        Test serialize verifies that exception InvalidContentType is raised
        """
        input_dict = dict(servers={'test': 'pass'})
        content_type = 'application/unknown'
        serializer = wsgi.Serializer()

        self.assertRaises(
            exception.InvalidContentType, serializer.serialize,
            input_dict, content_type)

    def test_get_deserialize_handler_unknown_content_type(self):
        """
        Test get deserialize verifies
        that exception InvalidContentType is raised
        """
        content_type = 'application/unknown'
        serializer = wsgi.Serializer()

        self.assertRaises(
            exception.InvalidContentType,
            serializer.get_deserialize_handler, content_type)


class RequestDeserializerTest(testtools.TestCase):
    def test_get_body_deserializer_unknown_content_type(self):
        """
        Test get body deserializer verifies
         that exception InvalidContentType is raised
        """
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
        """
        Test serialize verifies
        that exception InvalidContentType is raised
        """
        self.assertRaises(
            exception.InvalidContentType,
            self.serializer.serialize,
            {}, 'application/unknown')

    def test_get_body_serializer(self):
        """
        Test get body serializer verifies
        that exception InvalidContentType is raised
        """
        self.assertRaises(
            exception.InvalidContentType,
            self.serializer.get_body_serializer, 'application/unknown')


class XMLDeserializerTest(testtools.TestCase):
    def test_default_raise_Maiformed_Exception(self):
        """
        Test verifies that exception MalformedRequestBody is raised
        """
        data_string = ""
        deserializer = wsgi.XMLDeserializer()

        self.assertRaises(
            exception.MalformedRequestBody, deserializer.default, data_string)

    def test_entity_expansion(self):
        def killer_body():
            return (("""<!DOCTYPE x [
                    <!ENTITY a "%(a)s">
                    <!ENTITY b "%(b)s">
                    <!ENTITY c "%(c)s">]>
                <foo>
                    <bar>
                        <v1>%(d)s</v1>
                    </bar>
                </foo>""") % {
                'a': 'A' * 10,
                'b': '&a;' * 10,
                'c': '&b;' * 10,
                'd': '&c;' * 9999,
            }).strip()

        deserializer = wsgi.XMLDeserializer()
        self.assertRaises(
            ValueError, deserializer.default, killer_body())


class JSONDeserializerTest(testtools.TestCase):
    def test_default_raise_Maiformed_Exception(self):
        """
        Test verifies JsonDeserializer.default
        raises exception MalformedRequestBody correctly
        """
        data_string = ""
        deserializer = wsgi.JSONDeserializer()

        self.assertRaises(
            exception.MalformedRequestBody, deserializer.default, data_string)


class ResourceTest(testtools.TestCase):
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


class XMLDictSerializerTest(testtools.TestCase):
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
