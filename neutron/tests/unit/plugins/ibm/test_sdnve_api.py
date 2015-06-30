# Copyright 2014 IBM Corp.
#
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


import mock
from oslo_utils import uuidutils

from neutron.plugins.ibm.common import constants
from neutron.plugins.ibm import sdnve_api
from neutron.tests import base

RESOURCE_PATH = {
    'network': "ln/networks/",
}
RESOURCE = 'network'
HTTP_OK = 200
TENANT_ID = uuidutils.generate_uuid()


class TestSdnveApi(base.BaseTestCase):

    def setUp(self):
        super(TestSdnveApi, self).setUp()

        class MockKeystoneClient(object):
            def __init__(self, **kwargs):
                pass

            def get_tenant_name(self, id):
                return 'test tenant name'

        with mock.patch('neutron.plugins.ibm.sdnve_api.'
                        'KeystoneClient',
                        new=MockKeystoneClient):
            self.api = sdnve_api.Client()

    def mock_do_request(self, method, url, body=None, headers=None,
                        params=None, connection_type=None):
        return (HTTP_OK, url)

    def mock_do_request_tenant(self, method, url, body=None, headers=None,
                               params=None, connection_type=None):
        return (HTTP_OK, {'id': TENANT_ID,
                          'network_type': constants.TENANT_TYPE_OF})

    def mock_do_request_no_tenant(self, method, url, body=None, headers=None,
                                  params=None, connection_type=None):
        return (None, None)

    def mock_process_request(self, body):
        return body

    def test_sdnve_api_list(self):
        with mock.patch('neutron.plugins.ibm.sdnve_api.'
                        'Client.do_request',
                        new=self.mock_do_request):
            result = self.api.sdnve_list(RESOURCE)
            self.assertEqual(result, (HTTP_OK, RESOURCE_PATH[RESOURCE]))

    def test_sdnve_api_show(self):
        with mock.patch('neutron.plugins.ibm.sdnve_api.'
                        'Client.do_request',
                        new=self.mock_do_request):
            result = self.api.sdnve_show(RESOURCE, TENANT_ID)
            self.assertEqual(result,
                             (HTTP_OK, RESOURCE_PATH[RESOURCE] + TENANT_ID))

    def test_sdnve_api_create(self):
        with mock.patch('neutron.plugins.ibm.sdnve_api.'
                        'Client.do_request',
                        new=self.mock_do_request):
            with mock.patch('neutron.plugins.ibm.sdnve_api.'
                            'Client.process_request',
                            new=self.mock_process_request):
                result = self.api.sdnve_create(RESOURCE, '')
                self.assertEqual(result, (HTTP_OK, RESOURCE_PATH[RESOURCE]))

    def test_sdnve_api_update(self):
        with mock.patch('neutron.plugins.ibm.sdnve_api.'
                        'Client.do_request',
                        new=self.mock_do_request):
            with mock.patch('neutron.plugins.ibm.sdnve_api.'
                            'Client.process_request',
                            new=self.mock_process_request):
                result = self.api.sdnve_update(RESOURCE, TENANT_ID, '')
                self.assertEqual(result,
                                 (HTTP_OK,
                                  RESOURCE_PATH[RESOURCE] + TENANT_ID))

    def test_sdnve_api_delete(self):
        with mock.patch('neutron.plugins.ibm.sdnve_api.'
                        'Client.do_request',
                        new=self.mock_do_request):
            result = self.api.sdnve_delete(RESOURCE, TENANT_ID)
            self.assertEqual(result,
                             (HTTP_OK, RESOURCE_PATH[RESOURCE] + TENANT_ID))

    def test_sdnve_get_tenant_by_id(self):
        with mock.patch('neutron.plugins.ibm.sdnve_api.'
                        'Client.do_request',
                        new=self.mock_do_request_tenant):
            id = TENANT_ID
            result = self.api.sdnve_get_tenant_byid(id)
            self.assertEqual(result,
                             (TENANT_ID, constants.TENANT_TYPE_OF))

    def test_sdnve_check_and_create_tenant(self):
        with mock.patch('neutron.plugins.ibm.sdnve_api.'
                        'Client.do_request',
                        new=self.mock_do_request_tenant):
            id = TENANT_ID
            result = self.api.sdnve_check_and_create_tenant(id)
            self.assertEqual(result, TENANT_ID)

    def test_sdnve_check_and_create_tenant_fail(self):
        with mock.patch('neutron.plugins.ibm.sdnve_api.'
                        'Client.do_request',
                        new=self.mock_do_request_no_tenant):
            id = TENANT_ID
            result = self.api.sdnve_check_and_create_tenant(
                id, constants.TENANT_TYPE_OF)
            self.assertIsNone(result)

    def test_process_request(self):
        my_request = {'key_1': 'value_1', 'router:external': 'True',
                      'key_2': 'value_2'}
        expected = {'key_1': 'value_1', 'router_external': 'True',
                    'key_2': 'value_2'}
        result = self.api.process_request(my_request)
        self.assertEqual(expected, result)
