# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 Cisco Systems
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
#    @author: Tyler Smith, Cisco Systems

import logging
import unittest
import re

from quantum.common.serializer import Serializer
from quantum.client import Client

LOG = logging.getLogger('quantum.tests.test_api')

# Set a couple tenants to use for testing
TENANT_1 = 'totore'
TENANT_2 = 'totore2'


class ServerStub():
    """This class stubs a basic server for the API client to talk to"""

    class Response(object):
        """This class stubs a basic response to send the API client"""
        def __init__(self, content=None, status=None):
            self.content = content
            self.status = status

        def read(self):
            return self.content

        def status(self):
            return self.status

    # To test error codes, set the host to 10.0.0.1, and the port to the code
    def __init__(self, host, port=9696, key_file="", cert_file=""):
        self.host = host
        self.port = port
        self.key_file = key_file
        self.cert_file = cert_file

    def request(self, method, action, body, headers):
        self.method = method
        self.action = action
        self.body = body

    def status(self, status=None):
        return status or 200

    def getresponse(self):
        res = self.Response(status=self.status())

        # If the host is 10.0.0.1, return the port as an error code
        if self.host == "10.0.0.1":
            res.status = self.port
            return res

        # Extract important information from the action string to assure sanity
        match = re.search('tenants/(.+?)/(.+)\.(json|xml)$', self.action)

        tenant = match.group(1)
        path = match.group(2)
        format = match.group(3)

        data = {'data': {'method': self.method, 'action': self.action,
                         'body': self.body, 'tenant': tenant, 'path': path,
                         'format': format, 'key_file': self.key_file,
                         'cert_file': self.cert_file}}

        # Serialize it to the proper format so the API client can handle it
        if data['data']['format'] == 'json':
            res.content = Serializer().serialize(data, "application/json")
        else:
            res.content = Serializer().serialize(data, "application/xml")
        return res


class APITest(unittest.TestCase):

    def setUp(self):
        """ Setups a test environment for the API client """
        HOST = '127.0.0.1'
        PORT = 9696
        USE_SSL = False

        self.client = Client(HOST, PORT, USE_SSL, TENANT_1, 'json', ServerStub)

    def _assert_sanity(self, call, status, method, path, data=[], params={}):
        """ Perform common assertions to test the sanity of client requests """

        # Handle an error case first
        if status != 200:
            (self.client.host, self.client.port) = ("10.0.0.1", status)
            self.assertRaises(Exception, call, *data, **params)
            return

        # Make the call, then get the data from the root node and assert it
        data = call(*data, **params)['data']

        self.assertEqual(data['method'], method)
        self.assertEqual(data['format'], params['format'])
        self.assertEqual(data['tenant'], params['tenant'])
        self.assertEqual(data['path'], path)

        return data

    def _test_list_networks(self, tenant=TENANT_1, format='json', status=200):
        LOG.debug("_test_list_networks - tenant:%s "\
                  "- format:%s - START", format, tenant)

        self._assert_sanity(self.client.list_networks,
                            status,
                            "GET",
                            "networks",
                            data=[],
                            params={'tenant': tenant, 'format': format})

        LOG.debug("_test_list_networks - tenant:%s "\
                  "- format:%s - END", format, tenant)

    def _test_show_network_details(self,
                                   tenant=TENANT_1, format='json', status=200):
        LOG.debug("_test_show_network_details - tenant:%s "\
                  "- format:%s - START", format, tenant)

        self._assert_sanity(self.client.show_network_details,
                            status,
                            "GET",
                            "networks/001",
                            data=["001"],
                            params={'tenant': tenant, 'format': format})

        LOG.debug("_test_show_network_details - tenant:%s "\
                  "- format:%s - END", format, tenant)

    def _test_create_network(self, tenant=TENANT_1, format='json', status=200):
        LOG.debug("_test_create_network - tenant:%s "\
                  "- format:%s - START", format, tenant)

        self._assert_sanity(self.client.create_network,
                            status,
                            "POST",
                            "networks",
                            data=[{'network': {'net-name': 'testNetwork'}}],
                            params={'tenant': tenant, 'format': format})

        LOG.debug("_test_create_network - tenant:%s "\
                  "- format:%s - END", format, tenant)

    def _test_update_network(self, tenant=TENANT_1, format='json', status=200):
        LOG.debug("_test_update_network - tenant:%s "\
                  "- format:%s - START", format, tenant)

        self._assert_sanity(self.client.update_network,
                            status,
                            "PUT",
                            "networks/001",
                            data=["001",
                                  {'network': {'net-name': 'newName'}}],
                            params={'tenant': tenant, 'format': format})

        LOG.debug("_test_update_network - tenant:%s "\
                  "- format:%s - END", format, tenant)

    def _test_delete_network(self, tenant=TENANT_1, format='json', status=200):
        LOG.debug("_test_delete_network - tenant:%s "\
                  "- format:%s - START", format, tenant)

        self._assert_sanity(self.client.delete_network,
                            status,
                            "DELETE",
                            "networks/001",
                            data=["001"],
                            params={'tenant': tenant, 'format': format})

        LOG.debug("_test_delete_network - tenant:%s "\
                  "- format:%s - END", format, tenant)

    def _test_list_ports(self, tenant=TENANT_1, format='json', status=200):
        LOG.debug("_test_list_ports - tenant:%s "\
                  "- format:%s - START", format, tenant)

        self._assert_sanity(self.client.list_ports,
                            status,
                            "GET",
                            "networks/001/ports",
                            data=["001"],
                            params={'tenant': tenant, 'format': format})

        LOG.debug("_test_list_ports - tenant:%s "\
                  "- format:%s - END", format, tenant)

    def _test_show_port_details(self,
                                tenant=TENANT_1, format='json', status=200):
        LOG.debug("_test_show_port_details - tenant:%s "\
                  "- format:%s - START", format, tenant)

        self._assert_sanity(self.client.show_port_details,
                            status,
                            "GET",
                            "networks/001/ports/001",
                            data=["001", "001"],
                            params={'tenant': tenant, 'format': format})

        LOG.debug("_test_show_port_details - tenant:%s "\
                  "- format:%s - END", format, tenant)

    def _test_create_port(self, tenant=TENANT_1, format='json', status=200):
        LOG.debug("_test_create_port - tenant:%s "\
                  "- format:%s - START", format, tenant)

        self._assert_sanity(self.client.create_port,
                            status,
                            "POST",
                            "networks/001/ports",
                            data=["001"],
                            params={'tenant': tenant, 'format': format})

        LOG.debug("_test_create_port - tenant:%s "\
                  "- format:%s - END", format, tenant)

    def _test_delete_port(self, tenant=TENANT_1, format='json', status=200):
        LOG.debug("_test_delete_port - tenant:%s "\
                  "- format:%s - START", format, tenant)

        self._assert_sanity(self.client.delete_port,
                            status,
                            "DELETE",
                            "networks/001/ports/001",
                            data=["001", "001"],
                            params={'tenant': tenant, 'format': format})

        LOG.debug("_test_delete_port - tenant:%s "\
                  "- format:%s - END", format, tenant)

    def _test_update_port(self, tenant=TENANT_1, format='json', status=200):
        LOG.debug("_test_update_port - tenant:%s "\
                  "- format:%s - START", format, tenant)

        self._assert_sanity(self.client.update_port,
                            status,
                            "PUT",
                            "networks/001/ports/001",
                            data=["001", "001",
                                  {'port': {'state': 'ACTIVE'}}],
                            params={'tenant': tenant, 'format': format})

        LOG.debug("_test_update_port - tenant:%s "\
                  "- format:%s - END", format, tenant)

    def _test_show_port_attachment(self,
                                   tenant=TENANT_1, format='json', status=200):
        LOG.debug("_test_show_port_attachment - tenant:%s "\
                  "- format:%s - START", format, tenant)

        self._assert_sanity(self.client.show_port_attachment,
                            status,
                            "GET",
                            "networks/001/ports/001/attachment",
                            data=["001", "001"],
                            params={'tenant': tenant, 'format': format})

        LOG.debug("_test_show_port_attachment - tenant:%s "\
                  "- format:%s - END", format, tenant)

    def _test_attach_resource(self, tenant=TENANT_1,
                              format='json', status=200):
        LOG.debug("_test_attach_resource - tenant:%s "\
                  "- format:%s - START", format, tenant)

        self._assert_sanity(self.client.attach_resource,
                            status,
                            "PUT",
                            "networks/001/ports/001/attachment",
                            data=["001", "001",
                                    {'resource': {'id': '1234'}}],
                            params={'tenant': tenant, 'format': format})

        LOG.debug("_test_attach_resource - tenant:%s "\
                  "- format:%s - END", format, tenant)

    def _test_detach_resource(self, tenant=TENANT_1,
                              format='json', status=200):
        LOG.debug("_test_detach_resource - tenant:%s "\
                  "- format:%s - START", format, tenant)

        self._assert_sanity(self.client.detach_resource,
                            status,
                            "DELETE",
                            "networks/001/ports/001/attachment",
                            data=["001", "001"],
                            params={'tenant': tenant, 'format': format})

        LOG.debug("_test_detach_resource - tenant:%s "\
                  "- format:%s - END", format, tenant)

    def _test_ssl_certificates(self, tenant=TENANT_1,
                               format='json', status=200):
        LOG.debug("_test_ssl_certificates - tenant:%s "\
                  "- format:%s - START", format, tenant)

        # Set SSL, and our cert file
        self.client.use_ssl = True
        cert_file = "/fake.cert"
        self.client.key_file = self.client.cert_file = cert_file

        data = self._assert_sanity(self.client.list_networks,
                            status,
                            "GET",
                            "networks",
                            data=[],
                            params={'tenant': tenant, 'format': format})

        self.assertEquals(data["key_file"], cert_file)
        self.assertEquals(data["cert_file"], cert_file)

        LOG.debug("_test_ssl_certificates - tenant:%s "\
                  "- format:%s - END", format, tenant)

    def test_list_networks_json(self):
        self._test_list_networks(format='json')

    def test_list_networks_xml(self):
        self._test_list_networks(format='xml')

    def test_list_networks_alt_tenant(self):
        self._test_list_networks(tenant=TENANT_2)

    def test_list_networks_error_470(self):
        self._test_list_networks(status=470)

    def test_list_networks_error_401(self):
        self._test_list_networks(status=401)

    def test_show_network_details_json(self):
        self._test_show_network_details(format='json')

    def test_show_network_details_xml(self):
        self._test_show_network_details(format='xml')

    def test_show_network_details_alt_tenant(self):
        self._test_show_network_details(tenant=TENANT_2)

    def test_show_network_details_error_470(self):
        self._test_show_network_details(status=470)

    def test_show_network_details_error_401(self):
        self._test_show_network_details(status=401)

    def test_show_network_details_error_420(self):
        self._test_show_network_details(status=420)

    def test_create_network_json(self):
        self._test_create_network(format='json')

    def test_create_network_xml(self):
        self._test_create_network(format='xml')

    def test_create_network_alt_tenant(self):
        self._test_create_network(tenant=TENANT_2)

    def test_create_network_error_470(self):
        self._test_create_network(status=470)

    def test_create_network_error_401(self):
        self._test_create_network(status=401)

    def test_create_network_error_400(self):
        self._test_create_network(status=400)

    def test_create_network_error_422(self):
        self._test_create_network(status=422)

    def test_update_network_json(self):
        self._test_update_network(format='json')

    def test_update_network_xml(self):
        self._test_update_network(format='xml')

    def test_update_network_alt_tenant(self):
        self._test_update_network(tenant=TENANT_2)

    def test_update_network_error_470(self):
        self._test_update_network(status=470)

    def test_update_network_error_401(self):
        self._test_update_network(status=401)

    def test_update_network_error_400(self):
        self._test_update_network(status=400)

    def test_update_network_error_420(self):
        self._test_update_network(status=420)

    def test_update_network_error_422(self):
        self._test_update_network(status=422)

    def test_delete_network_json(self):
        self._test_delete_network(format='json')

    def test_delete_network_xml(self):
        self._test_delete_network(format='xml')

    def test_delete_network_alt_tenant(self):
        self._test_delete_network(tenant=TENANT_2)

    def test_delete_network_error_470(self):
        self._test_delete_network(status=470)

    def test_delete_network_error_401(self):
        self._test_delete_network(status=401)

    def test_delete_network_error_420(self):
        self._test_delete_network(status=420)

    def test_delete_network_error_421(self):
        self._test_delete_network(status=421)

    def test_list_ports_json(self):
        self._test_list_ports(format='json')

    def test_list_ports_xml(self):
        self._test_list_ports(format='xml')

    def test_list_ports_alt_tenant(self):
        self._test_list_ports(tenant=TENANT_2)

    def test_list_ports_error_470(self):
        self._test_list_ports(status=470)

    def test_list_ports_error_401(self):
        self._test_list_ports(status=401)

    def test_list_ports_error_420(self):
        self._test_list_ports(status=420)

    def test_show_port_details_json(self):
        self._test_list_ports(format='json')

    def test_show_port_details_xml(self):
        self._test_list_ports(format='xml')

    def test_show_port_details_alt_tenant(self):
        self._test_list_ports(tenant=TENANT_2)

    def test_show_port_details_error_470(self):
        self._test_show_port_details(status=470)

    def test_show_port_details_error_401(self):
        self._test_show_port_details(status=401)

    def test_show_port_details_error_420(self):
        self._test_show_port_details(status=420)

    def test_show_port_details_error_430(self):
        self._test_show_port_details(status=430)

    def test_create_port_json(self):
        self._test_create_port(format='json')

    def test_create_port_xml(self):
        self._test_create_port(format='xml')

    def test_create_port_alt_tenant(self):
        self._test_create_port(tenant=TENANT_2)

    def test_create_port_error_470(self):
        self._test_create_port(status=470)

    def test_create_port_error_401(self):
        self._test_create_port(status=401)

    def test_create_port_error_400(self):
        self._test_create_port(status=400)

    def test_create_port_error_420(self):
        self._test_create_port(status=420)

    def test_create_port_error_430(self):
        self._test_create_port(status=430)

    def test_create_port_error_431(self):
        self._test_create_port(status=431)

    def test_delete_port_json(self):
        self._test_delete_port(format='json')

    def test_delete_port_xml(self):
        self._test_delete_port(format='xml')

    def test_delete_port_alt_tenant(self):
        self._test_delete_port(tenant=TENANT_2)

    def test_delete_port_error_470(self):
        self._test_delete_port(status=470)

    def test_delete_port_error_401(self):
        self._test_delete_port(status=401)

    def test_delete_port_error_420(self):
        self._test_delete_port(status=420)

    def test_delete_port_error_430(self):
        self._test_delete_port(status=430)

    def test_delete_port_error_432(self):
        self._test_delete_port(status=432)

    def test_update_port_json(self):
        self._test_update_port(format='json')

    def test_update_port_xml(self):
        self._test_update_port(format='xml')

    def test_update_port_alt_tenant(self):
        self._test_update_port(tenant=TENANT_2)

    def test_update_port_error_470(self):
        self._test_update_port(status=470)

    def test_update_port_error_401(self):
        self._test_update_port(status=401)

    def test_update_port_error_400(self):
        self._test_update_port(status=400)

    def test_update_port_error_420(self):
        self._test_update_port(status=420)

    def test_update_port_error_430(self):
        self._test_update_port(status=430)

    def test_update_port_error_431(self):
        self._test_update_port(status=431)

    def test_show_port_attachment_json(self):
        self._test_show_port_attachment(format='json')

    def test_show_port_attachment_xml(self):
        self._test_show_port_attachment(format='xml')

    def test_show_port_attachment_alt_tenant(self):
        self._test_show_port_attachment(tenant=TENANT_2)

    def test_show_port_attachment_error_470(self):
        self._test_show_port_attachment(status=470)

    def test_show_port_attachment_error_401(self):
        self._test_show_port_attachment(status=401)

    def test_show_port_attachment_error_400(self):
        self._test_show_port_attachment(status=400)

    def test_show_port_attachment_error_420(self):
        self._test_show_port_attachment(status=420)

    def test_show_port_attachment_error_430(self):
        self._test_show_port_attachment(status=430)

    def test_attach_resource_json(self):
        self._test_attach_resource(format='json')

    def test_attach_resource_xml(self):
        self._test_attach_resource(format='xml')

    def test_attach_resource_alt_tenant(self):
        self._test_attach_resource(tenant=TENANT_2)

    def test_attach_resource_error_470(self):
        self._test_attach_resource(status=470)

    def test_attach_resource_error_401(self):
        self._test_attach_resource(status=401)

    def test_attach_resource_error_400(self):
        self._test_attach_resource(status=400)

    def test_attach_resource_error_420(self):
        self._test_attach_resource(status=420)

    def test_attach_resource_error_430(self):
        self._test_attach_resource(status=430)

    def test_attach_resource_error_432(self):
        self._test_attach_resource(status=432)

    def test_attach_resource_error_440(self):
        self._test_attach_resource(status=440)

    def test_detach_resource_json(self):
        self._test_detach_resource(format='json')

    def test_detach_resource_xml(self):
        self._test_detach_resource(format='xml')

    def test_detach_resource_alt_tenant(self):
        self._test_detach_resource(tenant=TENANT_2)

    def test_detach_resource_error_470(self):
        self._test_detach_resource(status=470)

    def test_detach_resource_error_401(self):
        self._test_detach_resource(status=401)

    def test_detach_resource_error_420(self):
        self._test_detach_resource(status=420)

    def test_detach_resource_error_430(self):
        self._test_detach_resource(status=430)

    def test_ssl_certificates(self):
        self._test_ssl_certificates()
