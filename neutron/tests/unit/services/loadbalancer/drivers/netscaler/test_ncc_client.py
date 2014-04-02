# Copyright 2014 Citrix Systems
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

import mock
import requests

from neutron.services.loadbalancer.drivers.netscaler import ncc_client
from neutron.services.loadbalancer.drivers.netscaler import netscaler_driver
from neutron.tests.unit import testlib_api

NCC_CLIENT_CLASS = ('neutron.services.loadbalancer.drivers'
                    '.netscaler.ncc_client.NSClient')

TESTURI_SCHEME = 'http'
TESTURI_HOSTNAME = '1.1.1.1'
TESTURI_PORT = 4433
TESTURI_PATH = '/ncc_service/1.0'
TESTURI = '%s://%s:%s%s' % (TESTURI_SCHEME, TESTURI_HOSTNAME,
                            TESTURI_PORT, TESTURI_PATH)
TEST_USERNAME = 'user211'
TEST_PASSWORD = '@30xHl5cT'
TEST_TENANT_ID = '9c5245a2-0432-9d4c-4829-9bd7028603a1'
TESTVIP_ID = '52ab5d71-6bb2-457f-8414-22a4ba55efec'


class TestNSClient(testlib_api.WebTestCase):

    """A Unit test for the NetScaler NCC client module."""

    def setUp(self):
        self.log = mock.patch.object(ncc_client, 'LOG').start()
        super(TestNSClient, self).setUp()
        # mock the requests.request function call
        self.request_method_mock = mock.Mock()
        requests.request = self.request_method_mock
        self.testclient = self._get_nsclient()

    def test_instantiate_nsclient_with_empty_uri(self):
        """Asserts that a call with empty URI will raise an exception."""
        self.assertRaises(ncc_client.NCCException, ncc_client.NSClient,
                          '', TEST_USERNAME, TEST_PASSWORD)

    def test_create_resource_with_no_connection(self):
        """Asserts that a call with no connection will raise an exception."""
        # mock a connection object that fails to establish a connection
        self.request_method_mock.side_effect = (
            requests.exceptions.ConnectionError())
        resource_path = netscaler_driver.VIPS_RESOURCE
        resource_name = netscaler_driver.VIP_RESOURCE
        resource_body = self._get_testvip_httpbody_for_create()
        # call method under test: create_resource() and assert that
        # it raises an exception
        self.assertRaises(ncc_client.NCCException,
                          self.testclient.create_resource,
                          TEST_TENANT_ID, resource_path,
                          resource_name, resource_body)

    def test_create_resource_with_error(self):
        """Asserts that a failed create call raises an exception."""
        # create a mock object to represent a valid http response
        # with a failure status code.
        fake_response = requests.Response()
        fake_response.status_code = requests.codes.unauthorized
        fake_response.headers = []
        requests.request.return_value = fake_response
        resource_path = netscaler_driver.VIPS_RESOURCE
        resource_name = netscaler_driver.VIP_RESOURCE
        resource_body = self._get_testvip_httpbody_for_create()
        # call method under test: create_resource
        # and assert that it raises the expected exception.
        self.assertRaises(ncc_client.NCCException,
                          self.testclient.create_resource,
                          TEST_TENANT_ID, resource_path,
                          resource_name, resource_body)

    def test_create_resource(self):
        """Asserts that a correct call will succeed."""
        # obtain the mock object that corresponds to the call of request()
        fake_response = requests.Response()
        fake_response.status_code = requests.codes.created
        fake_response.headers = []
        self.request_method_mock.return_value = fake_response
        resource_path = netscaler_driver.VIPS_RESOURCE
        resource_name = netscaler_driver.VIP_RESOURCE
        resource_body = self._get_testvip_httpbody_for_create()
        # call method under test: create_resource()
        self.testclient.create_resource(TEST_TENANT_ID, resource_path,
                                        resource_name, resource_body)
        # assert that request() was called
        # with the expected params.
        resource_url = "%s/%s" % (self.testclient.service_uri, resource_path)
        self.request_method_mock.assert_called_once_with(
            'POST',
            url=resource_url,
            headers=mock.ANY,
            data=mock.ANY)

    def test_update_resource_with_error(self):
        """Asserts that a failed update call raises an exception."""
        # create a valid http response with a failure status code.
        fake_response = requests.Response()
        fake_response.status_code = requests.codes.unauthorized
        fake_response.headers = []
        # obtain the mock object that corresponds to the call of request()
        self.request_method_mock.return_value = fake_response
        resource_path = "%s/%s" % (netscaler_driver.VIPS_RESOURCE,
                                   TESTVIP_ID)
        resource_name = netscaler_driver.VIP_RESOURCE
        resource_body = self._get_testvip_httpbody_for_update()
        # call method under test: update_resource() and
        # assert that it raises the expected exception.
        self.assertRaises(ncc_client.NCCException,
                          self.testclient.update_resource,
                          TEST_TENANT_ID, resource_path,
                          resource_name, resource_body)

    def test_update_resource(self):
        """Asserts that a correct update call will succeed."""
        # create a valid http response with a successful status code.
        fake_response = requests.Response()
        fake_response.status_code = requests.codes.ok
        fake_response.headers = []
        # obtain the mock object that corresponds to the call of request()
        self.request_method_mock.return_value = fake_response
        resource_path = "%s/%s" % (netscaler_driver.VIPS_RESOURCE,
                                   TESTVIP_ID)
        resource_name = netscaler_driver.VIP_RESOURCE
        resource_body = self._get_testvip_httpbody_for_update()
        # call method under test: update_resource.
        self.testclient.update_resource(TEST_TENANT_ID, resource_path,
                                        resource_name, resource_body)
        resource_url = "%s/%s" % (self.testclient.service_uri, resource_path)
        # assert that requests.request() was called with the
        # expected params.
        self.request_method_mock.assert_called_once_with(
            'PUT',
            url=resource_url,
            headers=mock.ANY,
            data=mock.ANY)

    def test_delete_resource_with_error(self):
        """Asserts that a failed delete call raises an exception."""
        # create a valid http response with a failure status code.
        fake_response = requests.Response()
        fake_response.status_code = requests.codes.unauthorized
        fake_response.headers = []
        resource_path = "%s/%s" % (netscaler_driver.VIPS_RESOURCE,
                                   TESTVIP_ID)
        # call method under test: create_resource
        self.assertRaises(ncc_client.NCCException,
                          self.testclient.remove_resource,
                          TEST_TENANT_ID, resource_path)

    def test_delete_resource(self):
        """Asserts that a correct delete call will succeed."""
        # create a valid http response with a failure status code.
        fake_response = requests.Response()
        fake_response.status_code = requests.codes.ok
        fake_response.headers = []
        # obtain the mock object that corresponds to the call of request()
        self.request_method_mock.return_value = fake_response
        resource_path = "%s/%s" % (netscaler_driver.VIPS_RESOURCE,
                                   TESTVIP_ID)
        resource_url = "%s/%s" % (self.testclient.service_uri, resource_path)
        # call method under test: create_resource
        self.testclient.remove_resource(TEST_TENANT_ID, resource_path)
        # assert that httplib.HTTPConnection request() was called with the
        # expected params
        self.request_method_mock.assert_called_once_with(
            'DELETE',
            url=resource_url,
            headers=mock.ANY,
            data=mock.ANY)

    def _get_nsclient(self):
        return ncc_client.NSClient(TESTURI, TEST_USERNAME, TEST_PASSWORD)

    def _get_testvip_httpbody_for_create(self):
        body = {
            'name': 'vip1',
            'address': '10.0.0.3',
            'pool_id': 'da477c13-24cd-4c9f-8c19-757a61ef3b9d',
            'protocol': 'HTTP',
            'protocol_port': 80,
            'admin_state_up': True,
        }
        return body

    def _get_testvip_httpbody_for_update(self):
        body = {}
        body['name'] = 'updated vip1'
        body['admin_state_up'] = False
        return body
