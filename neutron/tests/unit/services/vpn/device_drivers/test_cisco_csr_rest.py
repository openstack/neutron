# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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
#

import random
import re

import requests
from requests import exceptions as r_exc
from requests_mock.contrib import fixture as mock_fixture

from neutron.services.vpn.device_drivers import (
    cisco_csr_rest_client as csr_client)
from neutron.tests import base


dummy_policy_id = 'dummy-ipsec-policy-id-name'
BASE_URL = 'https://%s:55443/api/v1/'
LOCAL_URL = 'https://localhost:55443/api/v1/'

URI_HOSTNAME = 'global/host-name'
URI_USERS = 'global/local-users'
URI_AUTH = 'auth/token-services'
URI_INTERFACE_GE1 = 'interfaces/GigabitEthernet1'
URI_PSK = 'vpn-svc/ike/keyrings'
URI_PSK_ID = URI_PSK + '/%s'
URI_IKE_POLICY = 'vpn-svc/ike/policies'
URI_IKE_POLICY_ID = URI_IKE_POLICY + '/%s'
URI_IPSEC_POLICY = 'vpn-svc/ipsec/policies'
URI_IPSEC_POLICY_ID = URI_IPSEC_POLICY + '/%s'
URI_IPSEC_CONN = 'vpn-svc/site-to-site'
URI_IPSEC_CONN_ID = URI_IPSEC_CONN + '/%s'
URI_KEEPALIVE = 'vpn-svc/ike/keepalive'
URI_ROUTES = 'routing-svc/static-routes'
URI_ROUTES_ID = URI_ROUTES + '/%s'
URI_SESSIONS = 'vpn-svc/site-to-site/active/sessions'


# Note: Helper functions to test reuse of IDs.
def generate_pre_shared_key_id():
    return random.randint(100, 200)


def generate_ike_policy_id():
    return random.randint(200, 300)


def generate_ipsec_policy_id():
    return random.randint(300, 400)


class CiscoCsrBaseTestCase(base.BaseTestCase):

    """Helper methods to register mock intercepts - used by child classes."""

    def setUp(self, host='localhost', tunnel_ip='10.10.10.10', timeout=None):
        super(CiscoCsrBaseTestCase, self).setUp()
        self.base_url = BASE_URL % host
        self.requests = self.useFixture(mock_fixture.Fixture())
        info = {'rest_mgmt_ip': host, 'tunnel_ip': tunnel_ip,
                'username': 'stack', 'password': 'cisco', 'timeout': timeout}
        self.csr = csr_client.CsrRestClient(info)

    def _register_local_get(self, uri, json=None,
                            result_code=requests.codes.OK):
        self.requests.register_uri(
            'GET',
            LOCAL_URL + uri,
            status_code=result_code,
            json=json)

    def _register_local_post(self, uri, resource_id,
                             result_code=requests.codes.CREATED):
        self.requests.register_uri(
            'POST',
            LOCAL_URL + uri,
            status_code=result_code,
            headers={'location': LOCAL_URL + uri + '/' + str(resource_id)})

    def _register_local_delete(self, uri, resource_id, json=None,
                               result_code=requests.codes.NO_CONTENT):
        self.requests.register_uri(
            'DELETE',
            LOCAL_URL + uri + '/' + str(resource_id),
            status_code=result_code,
            json=json)

    def _register_local_delete_by_id(self, resource_id,
                                     result_code=requests.codes.NO_CONTENT):
        local_resource_re = re.compile(LOCAL_URL + '.+%s$' % resource_id)
        self.requests.register_uri(
            'DELETE',
            local_resource_re,
            status_code=result_code)

    def _register_local_put(self, uri, resource_id,
                            result_code=requests.codes.NO_CONTENT):
        self.requests.register_uri('PUT',
                                   LOCAL_URL + uri + '/' + resource_id,
                                   status_code=result_code)

    def _register_local_get_not_found(self, uri, resource_id,
                                      result_code=requests.codes.NOT_FOUND):
        self.requests.register_uri(
            'GET',
            LOCAL_URL + uri + '/' + str(resource_id),
            status_code=result_code)

    def _helper_register_auth_request(self):
        self.requests.register_uri('POST',
                                   LOCAL_URL + URI_AUTH,
                                   status_code=requests.codes.OK,
                                   json={'token-id': 'dummy-token'})

    def _helper_register_psk_post(self, psk_id):
        self._register_local_post(URI_PSK, psk_id)

    def _helper_register_ike_policy_post(self, policy_id):
        self._register_local_post(URI_IKE_POLICY, policy_id)

    def _helper_register_ipsec_policy_post(self, policy_id):
        self._register_local_post(URI_IPSEC_POLICY, policy_id)

    def _helper_register_tunnel_post(self, tunnel):
        self._register_local_post(URI_IPSEC_CONN, tunnel)


class TestCsrLoginRestApi(CiscoCsrBaseTestCase):

    """Test logging into CSR to obtain token-id."""

    def test_get_token(self):
        """Obtain the token and its expiration time."""
        self._helper_register_auth_request()
        self.assertTrue(self.csr.authenticate())
        self.assertEqual(requests.codes.OK, self.csr.status)
        self.assertIsNotNone(self.csr.token)

    def test_unauthorized_token_request(self):
        """Negative test of invalid user/password."""
        self.requests.register_uri('POST',
                                   LOCAL_URL + URI_AUTH,
                                   status_code=requests.codes.UNAUTHORIZED)
        self.csr.auth = ('stack', 'bogus')
        self.assertIsNone(self.csr.authenticate())
        self.assertEqual(requests.codes.UNAUTHORIZED, self.csr.status)

    def _simulate_wrong_host(self, request):
        if 'wrong-host' in request.url:
            raise r_exc.ConnectionError()

    def test_non_existent_host(self):
        """Negative test of request to non-existent host."""
        self.requests.add_matcher(self._simulate_wrong_host)
        self.csr.host = 'wrong-host'
        self.csr.token = 'Set by some previously successful access'
        self.assertIsNone(self.csr.authenticate())
        self.assertEqual(requests.codes.NOT_FOUND, self.csr.status)
        self.assertIsNone(self.csr.token)

    def _simulate_token_timeout(self, request):
        raise r_exc.Timeout()

    def test_timeout_on_token_access(self):
        """Negative test of a timeout on a request."""
        self.requests.add_matcher(self._simulate_token_timeout)
        self.assertIsNone(self.csr.authenticate())
        self.assertEqual(requests.codes.REQUEST_TIMEOUT, self.csr.status)
        self.assertIsNone(self.csr.token)


class TestCsrGetRestApi(CiscoCsrBaseTestCase):

    """Test CSR GET REST API."""

    def test_valid_rest_gets(self):
        """Simple GET requests.

        First request will do a post to get token (login). Assumes
        that there are two interfaces on the CSR.
        """

        self._helper_register_auth_request()
        self._register_local_get(URI_HOSTNAME,
                                 json={u'kind': u'object#host-name',
                                       u'host-name': u'Router'})
        self._register_local_get(URI_USERS,
                                 json={u'kind': u'collection#local-user',
                                       u'users': ['peter', 'paul', 'mary']})

        actual = self.csr.get_request(URI_HOSTNAME)
        self.assertEqual(requests.codes.OK, self.csr.status)
        self.assertIn('host-name', actual)
        self.assertIsNotNone(actual['host-name'])

        actual = self.csr.get_request(URI_USERS)
        self.assertEqual(requests.codes.OK, self.csr.status)
        self.assertIn('users', actual)


class TestCsrPostRestApi(CiscoCsrBaseTestCase):

    """Test CSR POST REST API."""

    def setUp(self, host='localhost', tunnel_ip='10.10.10.10', timeout=None):
        """Setup for each test in this suite.

        Each test case will have a normal authentication mock response
        registered here, although they may replace it, as needed.
        """
        super(TestCsrPostRestApi, self).setUp(host, tunnel_ip, timeout)
        self._helper_register_auth_request()

    def test_post_requests(self):
        """Simple POST requests (repeatable).

        First request will do a post to get token (login). Assumes
        that there are two interfaces (Ge1 and Ge2) on the CSR.
        """

        interface_re = re.compile('https://localhost:55443/.*/interfaces/'
                                  'GigabitEthernet\d/statistics')
        self.requests.register_uri('POST',
                                   interface_re,
                                   status_code=requests.codes.NO_CONTENT)

        actual = self.csr.post_request(
            'interfaces/GigabitEthernet1/statistics',
            payload={'action': 'clear'})
        self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)
        self.assertIsNone(actual)
        actual = self.csr.post_request(
            'interfaces/GigabitEthernet2/statistics',
            payload={'action': 'clear'})
        self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)
        self.assertIsNone(actual)

    def test_post_with_location(self):
        """Create a user and verify that location returned."""
        self.requests.register_uri(
            'POST',
            LOCAL_URL + URI_USERS,
            status_code=requests.codes.CREATED,
            headers={'location': LOCAL_URL + URI_USERS + '/test-user'})
        location = self.csr.post_request(
            URI_USERS,
            payload={'username': 'test-user',
                     'password': 'pass12345',
                     'privilege': 15})
        self.assertEqual(requests.codes.CREATED, self.csr.status)
        self.assertIn(URI_USERS + '/test-user', location)

    def test_post_missing_required_attribute(self):
        """Negative test of POST with missing mandatory info."""
        self.requests.register_uri('POST',
                                   LOCAL_URL + URI_USERS,
                                   status_code=requests.codes.BAD_REQUEST)
        self.csr.post_request(URI_USERS,
                              payload={'password': 'pass12345',
                                       'privilege': 15})
        self.assertEqual(requests.codes.BAD_REQUEST, self.csr.status)

    def test_post_invalid_attribute(self):
        """Negative test of POST with invalid info."""
        self.requests.register_uri('POST',
                                   LOCAL_URL + URI_USERS,
                                   status_code=requests.codes.BAD_REQUEST)
        self.csr.post_request(URI_USERS,
                              payload={'username': 'test-user',
                                       'password': 'pass12345',
                                       'privilege': 20})
        self.assertEqual(requests.codes.BAD_REQUEST, self.csr.status)

    def test_post_already_exists(self):
        """Negative test of a duplicate POST.

        Uses the lower level _do_request() API to just perform the POST and
        obtain the response, without any error processing.
        """

        self.requests.register_uri(
            'POST',
            LOCAL_URL + URI_USERS,
            status_code=requests.codes.CREATED,
            headers={'location': LOCAL_URL + URI_USERS + '/test-user'})

        location = self.csr._do_request(
            'POST',
            URI_USERS,
            payload={'username': 'test-user',
                     'password': 'pass12345',
                     'privilege': 15},
            more_headers=csr_client.HEADER_CONTENT_TYPE_JSON)
        self.assertEqual(requests.codes.CREATED, self.csr.status)
        self.assertIn(URI_USERS + '/test-user', location)
        self.csr.post_request(URI_USERS,
                              payload={'username': 'test-user',
                                       'password': 'pass12345',
                                       'privilege': 20})

        self.requests.register_uri(
            'POST',
            LOCAL_URL + URI_USERS,
            status_code=requests.codes.NOT_FOUND,
            json={u'error-code': -1,
                  u'error-message': u'user test-user already exists'})

        self.csr._do_request(
            'POST',
            URI_USERS,
            payload={'username': 'test-user',
                     'password': 'pass12345',
                     'privilege': 15},
            more_headers=csr_client.HEADER_CONTENT_TYPE_JSON)
        # Note: For local-user, a 404 error is returned. For
        # site-to-site connection a 400 is returned.
        self.assertEqual(requests.codes.NOT_FOUND, self.csr.status)

    def test_post_changing_value(self):
        """Negative test of a POST trying to change a value."""
        self.requests.register_uri(
            'POST',
            LOCAL_URL + URI_USERS,
            status_code=requests.codes.CREATED,
            headers={'location': LOCAL_URL + URI_USERS + '/test-user'})

        location = self.csr.post_request(
            URI_USERS,
            payload={'username': 'test-user',
                     'password': 'pass12345',
                     'privilege': 15})
        self.assertEqual(requests.codes.CREATED, self.csr.status)
        self.assertIn(URI_USERS + '/test-user', location)

        self.requests.register_uri(
            'POST',
            LOCAL_URL + URI_USERS,
            status_code=requests.codes.NOT_FOUND,
            json={u'error-code': -1,
                  u'error-message': u'user test-user already exists'})

        actual = self.csr.post_request(URI_USERS,
                                       payload={'username': 'test-user',
                                                'password': 'changed',
                                                'privilege': 15})
        self.assertEqual(requests.codes.NOT_FOUND, self.csr.status)
        expected = {u'error-code': -1,
                    u'error-message': u'user test-user already exists'}
        self.assertDictSupersetOf(expected, actual)


class TestCsrPutRestApi(CiscoCsrBaseTestCase):

    """Test CSR PUT REST API."""

    def _save_resources(self):
        self._register_local_get(URI_HOSTNAME,
                                 json={u'kind': u'object#host-name',
                                       u'host-name': u'Router'})
        interface_info = {u'kind': u'object#interface',
                          u'description': u'Changed description',
                          u'if-name': 'interfaces/GigabitEthernet1',
                          u'proxy-arp': True,
                          u'subnet-mask': u'255.255.255.0',
                          u'icmp-unreachable': True,
                          u'nat-direction': u'',
                          u'icmp-redirects': True,
                          u'ip-address': u'192.168.200.1',
                          u'verify-unicast-source': False,
                          u'type': u'ethernet'}
        self._register_local_get(URI_INTERFACE_GE1,
                                 json=interface_info)
        details = self.csr.get_request(URI_HOSTNAME)
        if self.csr.status != requests.codes.OK:
            self.fail("Unable to save original host name")
        self.original_host = details['host-name']
        details = self.csr.get_request(URI_INTERFACE_GE1)
        if self.csr.status != requests.codes.OK:
            self.fail("Unable to save interface Ge1 description")
        self.original_if = details
        self.csr.token = None

    def _restore_resources(self, user, password):
        """Restore the host name and interface description.

        Must restore the user and password, so that authentication
        token can be obtained (as some tests corrupt auth info).
        Will also clear token, so that it gets a fresh token.
        """

        self._register_local_put('global', 'host-name')
        self._register_local_put('interfaces', 'GigabitEthernet1')

        self.csr.auth = (user, password)
        self.csr.token = None
        payload = {'host-name': self.original_host}
        self.csr.put_request(URI_HOSTNAME, payload=payload)
        if self.csr.status != requests.codes.NO_CONTENT:
            self.fail("Unable to restore host name after test")
        payload = {'description': self.original_if['description'],
                   'if-name': self.original_if['if-name'],
                   'ip-address': self.original_if['ip-address'],
                   'subnet-mask': self.original_if['subnet-mask'],
                   'type': self.original_if['type']}
        self.csr.put_request(URI_INTERFACE_GE1,
                             payload=payload)
        if self.csr.status != requests.codes.NO_CONTENT:
            self.fail("Unable to restore I/F Ge1 description after test")

    def setUp(self, host='localhost', tunnel_ip='10.10.10.10', timeout=None):
        """Setup for each test in this suite.

        Each test case will have a normal authentication mock response
        registered here, although they may replace it, as needed. In
        addition, resources are saved, before each test is run, and
        restored, after each test completes.
        """
        super(TestCsrPutRestApi, self).setUp(host, tunnel_ip, timeout)
        self._helper_register_auth_request()
        self._save_resources()
        self.addCleanup(self._restore_resources, 'stack', 'cisco')

    def test_put_requests(self):
        """Simple PUT requests (repeatable).

        First request will do a post to get token (login). Assumes
        that there are two interfaces on the CSR (Ge1 and Ge2).
        """

        self._register_local_put('interfaces', 'GigabitEthernet1')
        self._register_local_put('global', 'host-name')

        actual = self.csr.put_request(URI_HOSTNAME,
                                      payload={'host-name': 'TestHost'})
        self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)
        self.assertIsNone(actual)

        actual = self.csr.put_request(URI_HOSTNAME,
                                      payload={'host-name': 'TestHost2'})
        self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)
        self.assertIsNone(actual)

    def test_change_interface_description(self):
        """Test that interface description can be changed.

        This was a problem with an earlier version of the CSR image and is
        here to prevent regression.
        """
        self._register_local_put('interfaces', 'GigabitEthernet1')
        payload = {'description': u'Changed description',
                   'if-name': self.original_if['if-name'],
                   'ip-address': self.original_if['ip-address'],
                   'subnet-mask': self.original_if['subnet-mask'],
                   'type': self.original_if['type']}
        actual = self.csr.put_request(URI_INTERFACE_GE1, payload=payload)
        self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)
        self.assertIsNone(actual)
        actual = self.csr.get_request(URI_INTERFACE_GE1)
        self.assertEqual(requests.codes.OK, self.csr.status)
        self.assertIn('description', actual)
        self.assertEqual(u'Changed description',
                         actual['description'])

    def ignore_test_change_to_empty_interface_description(self):
        """Test that interface description can be changed to empty string.

        This is here to prevent regression, where the CSR was rejecting
        an attempt to set the description to an empty string.
        """
        self._register_local_put('interfaces', 'GigabitEthernet1')
        payload = {'description': '',
                   'if-name': self.original_if['if-name'],
                   'ip-address': self.original_if['ip-address'],
                   'subnet-mask': self.original_if['subnet-mask'],
                   'type': self.original_if['type']}
        actual = self.csr.put_request(URI_INTERFACE_GE1, payload=payload)
        self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)
        self.assertIsNone(actual)
        actual = self.csr.get_request(URI_INTERFACE_GE1)
        self.assertEqual(requests.codes.OK, self.csr.status)
        self.assertIn('description', actual)
        self.assertEqual('', actual['description'])


class TestCsrDeleteRestApi(CiscoCsrBaseTestCase):

    """Test CSR DELETE REST API."""

    def setUp(self, host='localhost', tunnel_ip='10.10.10.10', timeout=None):
        """Setup for each test in this suite.

        Each test case will have a normal authentication mock response
        registered here, although they may replace it, as needed.
        """
        super(TestCsrDeleteRestApi, self).setUp(host, tunnel_ip, timeout)
        self._helper_register_auth_request()

    def _make_dummy_user(self):
        """Create a user that will be later deleted."""
        self.requests.register_uri(
            'POST',
            LOCAL_URL + URI_USERS,
            status_code=requests.codes.CREATED,
            headers={'location': LOCAL_URL + URI_USERS + '/dummy'})
        self.csr.post_request(URI_USERS,
                              payload={'username': 'dummy',
                                       'password': 'dummy',
                                       'privilege': 15})
        self.assertEqual(requests.codes.CREATED, self.csr.status)

    def test_delete_requests(self):
        """Simple DELETE requests (creating entry first)."""
        self._register_local_delete(URI_USERS, 'dummy')
        self._make_dummy_user()
        self.csr.token = None  # Force login
        self.csr.delete_request(URI_USERS + '/dummy')
        self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)
        # Delete again, but without logging in this time
        self._make_dummy_user()
        self.csr.delete_request(URI_USERS + '/dummy')
        self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)

    def test_delete_non_existent_entry(self):
        """Negative test of trying to delete a non-existent user."""
        expected = {u'error-code': -1,
                    u'error-message': u'user unknown not found'}
        self._register_local_delete(URI_USERS, 'unknown',
                                    result_code=requests.codes.NOT_FOUND,
                                    json=expected)
        actual = self.csr.delete_request(URI_USERS + '/unknown')
        self.assertEqual(requests.codes.NOT_FOUND, self.csr.status)
        self.assertDictSupersetOf(expected, actual)

    def test_delete_not_allowed(self):
        """Negative test of trying to delete the host-name."""
        self._register_local_delete(
            'global', 'host-name',
            result_code=requests.codes.METHOD_NOT_ALLOWED)
        self.csr.delete_request(URI_HOSTNAME)
        self.assertEqual(requests.codes.METHOD_NOT_ALLOWED,
                         self.csr.status)


class TestCsrRestApiFailures(CiscoCsrBaseTestCase):

    """Test failure cases common for all REST APIs.

    Uses the lower level _do_request() to just perform the operation and get
    the result, without any error handling.
    """

    def setUp(self, host='localhost', tunnel_ip='10.10.10.10', timeout=0.1):
        """Setup for each test in this suite.

        Each test case will have a normal authentication mock response
        registered here, although they may replace it, as needed.
        """
        super(TestCsrRestApiFailures, self).setUp(host, tunnel_ip, timeout)
        self._helper_register_auth_request()

    def _simulate_timeout(self, request):
        if URI_HOSTNAME in request.path_uri:
            raise r_exc.Timeout()

    def test_request_for_non_existent_resource(self):
        """Negative test of non-existent resource on REST request."""
        self.requests.register_uri('POST',
                                   LOCAL_URL + 'no/such/request',
                                   status_code=requests.codes.NOT_FOUND)
        self.csr.post_request('no/such/request')
        self.assertEqual(requests.codes.NOT_FOUND, self.csr.status)
        # The result is HTTP 404 message, so no error content to check

    def _simulate_get_timeout(self, request):
        """Will raise exception for any host request to this resource."""
        if URI_HOSTNAME in request.path_url:
            raise r_exc.Timeout()

    def test_timeout_during_request(self):
        """Negative test of timeout during REST request."""
        self.requests.add_matcher(self._simulate_get_timeout)
        self.csr._do_request('GET', URI_HOSTNAME)
        self.assertEqual(requests.codes.REQUEST_TIMEOUT, self.csr.status)

    def _simulate_auth_failure(self, request):
        """First time auth POST is done, re-report unauthorized."""
        if URI_AUTH in request.path_url and not self.called_once:
            self.called_once = True
            resp = requests.Response()
            resp.status_code = requests.codes.UNAUTHORIZED
            return resp

    def test_token_expired_on_request(self):
        """Token expired before trying a REST request.

        First, the token is set to a bogus value, to force it to
        try to authenticate on the GET request. Second, a mock that
        runs once, will simulate an auth failure. Third, the normal
        auth mock will simulate success.
        """

        self._register_local_get(URI_HOSTNAME,
                                 json={u'kind': u'object#host-name',
                                       u'host-name': u'Router'})
        self.called_once = False
        self.requests.add_matcher(self._simulate_auth_failure)
        self.csr.token = '123'  # These are 44 characters, so won't match
        actual = self.csr._do_request('GET', URI_HOSTNAME)
        self.assertEqual(requests.codes.OK, self.csr.status)
        self.assertIn('host-name', actual)
        self.assertIsNotNone(actual['host-name'])

    def test_failed_to_obtain_token_for_request(self):
        """Negative test of unauthorized user for REST request."""
        self.csr.auth = ('stack', 'bogus')
        self._register_local_get(URI_HOSTNAME,
                                 result_code=requests.codes.UNAUTHORIZED)
        self.csr._do_request('GET', URI_HOSTNAME)
        self.assertEqual(requests.codes.UNAUTHORIZED, self.csr.status)


class TestCsrRestIkePolicyCreate(CiscoCsrBaseTestCase):

    """Test IKE policy create REST requests."""

    def setUp(self, host='localhost', tunnel_ip='10.10.10.10', timeout=None):
        """Setup for each test in this suite.

        Each test case will have a normal authentication and post mock
        response registered, although the test may replace them, if needed.
        """
        super(TestCsrRestIkePolicyCreate, self).setUp(host, tunnel_ip, timeout)
        self._helper_register_auth_request()
        self._helper_register_ike_policy_post(2)

    def _helper_register_ike_policy_get(self):
        content = {u'kind': u'object#ike-policy',
                   u'priority-id': u'2',
                   u'version': u'v1',
                   u'local-auth-method': u'pre-share',
                   u'encryption': u'aes256',
                   u'hash': u'sha',
                   u'dhGroup': 5,
                   u'lifetime': 3600}
        self._register_local_get(URI_IKE_POLICY_ID % '2', json=content)

    def test_create_delete_ike_policy(self):
        """Create and then delete IKE policy."""
        self._helper_register_ike_policy_get()
        policy_info = {u'priority-id': u'2',
                       u'encryption': u'aes256',
                       u'hash': u'sha',
                       u'dhGroup': 5,
                       u'lifetime': 3600}
        location = self.csr.create_ike_policy(policy_info)
        self.assertEqual(requests.codes.CREATED, self.csr.status)
        self.assertIn(URI_IKE_POLICY_ID % '2', location)
        # Check the hard-coded items that get set as well...
        actual = self.csr.get_request(location, full_url=True)
        self.assertEqual(requests.codes.OK, self.csr.status)
        expected_policy = {u'kind': u'object#ike-policy',
                           u'version': u'v1',
                           u'local-auth-method': u'pre-share'}
        expected_policy.update(policy_info)
        self.assertEqual(expected_policy, actual)

        # Now delete and verify the IKE policy is gone
        self._register_local_delete(URI_IKE_POLICY, 2)
        self._register_local_get_not_found(URI_IKE_POLICY, 2)

        self.csr.delete_ike_policy(2)
        self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)
        actual = self.csr.get_request(location, full_url=True)
        self.assertEqual(requests.codes.NOT_FOUND, self.csr.status)

    def test_create_ike_policy_with_defaults(self):
        """Create IKE policy using defaults for all optional values."""
        policy = {u'kind': u'object#ike-policy',
                  u'priority-id': u'2',
                  u'version': u'v1',
                  u'local-auth-method': u'pre-share',
                  u'encryption': u'des',
                  u'hash': u'sha',
                  u'dhGroup': 1,
                  u'lifetime': 86400}
        self._register_local_get(URI_IKE_POLICY_ID % '2', json=policy)
        policy_info = {u'priority-id': u'2'}
        location = self.csr.create_ike_policy(policy_info)
        self.assertEqual(requests.codes.CREATED, self.csr.status)
        self.assertIn(URI_IKE_POLICY_ID % '2', location)

        # Check the hard-coded items that get set as well...
        actual = self.csr.get_request(location, full_url=True)
        self.assertEqual(requests.codes.OK, self.csr.status)
        expected_policy = {u'kind': u'object#ike-policy',
                           u'version': u'v1',
                           u'encryption': u'des',
                           u'hash': u'sha',
                           u'dhGroup': 1,
                           u'lifetime': 86400,
                           # Lower level sets this, but it is the default
                           u'local-auth-method': u'pre-share'}
        expected_policy.update(policy_info)
        self.assertEqual(expected_policy, actual)

    def test_create_duplicate_ike_policy(self):
        """Negative test of trying to create a duplicate IKE policy."""
        self._helper_register_ike_policy_get()
        policy_info = {u'priority-id': u'2',
                       u'encryption': u'aes',
                       u'hash': u'sha',
                       u'dhGroup': 5,
                       u'lifetime': 3600}
        location = self.csr.create_ike_policy(policy_info)
        self.assertEqual(requests.codes.CREATED, self.csr.status)
        self.assertIn(URI_IKE_POLICY_ID % '2', location)
        self.requests.register_uri(
            'POST',
            LOCAL_URL + URI_IKE_POLICY,
            status_code=requests.codes.BAD_REQUEST,
            json={u'error-code': -1,
                  u'error-message': u'policy 2 exist, not allow to '
                                    u'update policy using POST method'})
        location = self.csr.create_ike_policy(policy_info)
        self.assertEqual(requests.codes.BAD_REQUEST, self.csr.status)
        expected = {u'error-code': -1,
                    u'error-message': u'policy 2 exist, not allow to '
                    u'update policy using POST method'}
        self.assertDictSupersetOf(expected, location)


class TestCsrRestIPSecPolicyCreate(CiscoCsrBaseTestCase):

    """Test IPSec policy create REST requests."""

    def setUp(self, host='localhost', tunnel_ip='10.10.10.10', timeout=None):
        """Set up for each test in this suite.

        Each test case will have a normal authentication and post mock
        response registered, although the test may replace them, if needed.
        """
        super(TestCsrRestIPSecPolicyCreate, self).setUp(host,
                                                        tunnel_ip,
                                                        timeout)
        self._helper_register_auth_request()
        self._helper_register_ipsec_policy_post(123)

    def _helper_register_ipsec_policy_get(self, override=None):
        content = {u'kind': u'object#ipsec-policy',
                   u'mode': u'tunnel',
                   u'policy-id': u'123',
                   u'protection-suite': {
                       u'esp-encryption': u'esp-256-aes',
                       u'esp-authentication': u'esp-sha-hmac',
                       u'ah': u'ah-sha-hmac',
                   },
                   u'anti-replay-window-size': u'Disable',
                   u'lifetime-sec': 120,
                   u'pfs': u'group5',
                   u'lifetime-kb': 4608000,
                   u'idle-time': None}
        if override:
            content.update(override)
        self._register_local_get(URI_IPSEC_POLICY + '/123', json=content)

    def test_create_delete_ipsec_policy(self):
        """Create and then delete IPSec policy."""
        policy_info = {
            u'policy-id': u'123',
            u'protection-suite': {
                u'esp-encryption': u'esp-256-aes',
                u'esp-authentication': u'esp-sha-hmac',
                u'ah': u'ah-sha-hmac',
            },
            u'lifetime-sec': 120,
            u'pfs': u'group5',
            u'anti-replay-window-size': u'disable'
        }
        location = self.csr.create_ipsec_policy(policy_info)
        self.assertEqual(requests.codes.CREATED, self.csr.status)
        self.assertIn(URI_IPSEC_POLICY + '/123', location)

        # Check the hard-coded items that get set as well...
        self._helper_register_ipsec_policy_get()
        actual = self.csr.get_request(location, full_url=True)
        self.assertEqual(requests.codes.OK, self.csr.status)
        expected_policy = {u'kind': u'object#ipsec-policy',
                           u'mode': u'tunnel',
                           u'lifetime-kb': 4608000,
                           u'idle-time': None}
        expected_policy.update(policy_info)
        # CSR will respond with capitalized value
        expected_policy[u'anti-replay-window-size'] = u'Disable'
        self.assertEqual(expected_policy, actual)

        # Now delete and verify the IPSec policy is gone
        self._register_local_delete(URI_IPSEC_POLICY, 123)
        self._register_local_get_not_found(URI_IPSEC_POLICY, 123)

        self.csr.delete_ipsec_policy('123')
        self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)
        actual = self.csr.get_request(location, full_url=True)
        self.assertEqual(requests.codes.NOT_FOUND, self.csr.status)

    def test_create_ipsec_policy_with_defaults(self):
        """Create IPSec policy with default for all optional values."""
        policy_info = {u'policy-id': u'123'}
        location = self.csr.create_ipsec_policy(policy_info)
        self.assertEqual(requests.codes.CREATED, self.csr.status)
        self.assertIn(URI_IPSEC_POLICY + '/123', location)

        # Check the hard-coded items that get set as well...
        expected_policy = {u'kind': u'object#ipsec-policy',
                           u'mode': u'tunnel',
                           u'policy-id': u'123',
                           u'protection-suite': {},
                           u'lifetime-sec': 3600,
                           u'pfs': u'Disable',
                           u'anti-replay-window-size': u'None',
                           u'lifetime-kb': 4608000,
                           u'idle-time': None}
        self._register_local_get(URI_IPSEC_POLICY + '/123',
                                 json=expected_policy)

        actual = self.csr.get_request(location, full_url=True)
        self.assertEqual(requests.codes.OK, self.csr.status)
        self.assertEqual(expected_policy, actual)

    def test_create_ipsec_policy_with_uuid(self):
        """Create IPSec policy using UUID for id."""
        # Override normal POST response w/one that has a different policy ID
        self._helper_register_ipsec_policy_post(dummy_policy_id)
        policy_info = {
            u'policy-id': u'%s' % dummy_policy_id,
            u'protection-suite': {
                u'esp-encryption': u'esp-256-aes',
                u'esp-authentication': u'esp-sha-hmac',
                u'ah': u'ah-sha-hmac',
            },
            u'lifetime-sec': 120,
            u'pfs': u'group5',
            u'anti-replay-window-size': u'disable'
        }
        location = self.csr.create_ipsec_policy(policy_info)
        self.assertEqual(requests.codes.CREATED, self.csr.status)
        self.assertIn(URI_IPSEC_POLICY_ID % dummy_policy_id, location)

        # Check the hard-coded items that get set as well...
        expected_policy = {u'kind': u'object#ipsec-policy',
                           u'mode': u'tunnel',
                           u'lifetime-kb': 4608000,
                           u'idle-time': None}
        expected_policy.update(policy_info)
        # CSR will respond with capitalized value
        expected_policy[u'anti-replay-window-size'] = u'Disable'
        self._register_local_get(URI_IPSEC_POLICY_ID % dummy_policy_id,
                                 json=expected_policy)
        actual = self.csr.get_request(location, full_url=True)
        self.assertEqual(requests.codes.OK, self.csr.status)
        self.assertEqual(expected_policy, actual)

    def test_create_ipsec_policy_without_ah(self):
        """Create IPSec policy."""
        policy_info = {
            u'policy-id': u'123',
            u'protection-suite': {
                u'esp-encryption': u'esp-aes',
                u'esp-authentication': u'esp-sha-hmac',
            },
            u'lifetime-sec': 120,
            u'pfs': u'group5',
            u'anti-replay-window-size': u'128'
        }
        location = self.csr.create_ipsec_policy(policy_info)
        self.assertEqual(requests.codes.CREATED, self.csr.status)
        self.assertIn(URI_IPSEC_POLICY_ID % '123', location)

        # Check the hard-coded items that get set as well...
        self._helper_register_ipsec_policy_get(
            override={u'anti-replay-window-size': u'128',
                      u'protection-suite': {
                          u'esp-encryption': u'esp-aes',
                          u'esp-authentication': u'esp-sha-hmac'}})

        actual = self.csr.get_request(location, full_url=True)
        self.assertEqual(requests.codes.OK, self.csr.status)
        expected_policy = {u'kind': u'object#ipsec-policy',
                           u'mode': u'tunnel',
                           u'lifetime-kb': 4608000,
                           u'idle-time': None}
        expected_policy.update(policy_info)
        self.assertEqual(expected_policy, actual)

    def test_invalid_ipsec_policy_lifetime(self):
        """Failure test of IPSec policy with unsupported lifetime."""
        # Override normal POST response with one that indicates bad request
        self.requests.register_uri('POST',
                                   LOCAL_URL + URI_IPSEC_POLICY,
                                   status_code=requests.codes.BAD_REQUEST)
        policy_info = {
            u'policy-id': u'123',
            u'protection-suite': {
                u'esp-encryption': u'esp-aes',
                u'esp-authentication': u'esp-sha-hmac',
                u'ah': u'ah-sha-hmac',
            },
            u'lifetime-sec': 119,
            u'pfs': u'group5',
            u'anti-replay-window-size': u'128'
        }
        self.csr.create_ipsec_policy(policy_info)
        self.assertEqual(requests.codes.BAD_REQUEST, self.csr.status)

    def test_create_ipsec_policy_with_invalid_name(self):
        """Failure test of creating IPSec policy with name too long."""
        # Override normal POST response with one that indicates bad request
        self.requests.register_uri('POST',
                                   LOCAL_URL + URI_IPSEC_POLICY,
                                   status_code=requests.codes.BAD_REQUEST)
        policy_info = {u'policy-id': u'policy-name-is-too-long-32-chars'}
        self.csr.create_ipsec_policy(policy_info)
        self.assertEqual(requests.codes.BAD_REQUEST, self.csr.status)


class TestCsrRestPreSharedKeyCreate(CiscoCsrBaseTestCase):

    """Test Pre-shared key (PSK) create REST requests."""

    def setUp(self, host='localhost', tunnel_ip='10.10.10.10', timeout=None):
        """Set up for each test in this suite.

        Each test case will have a normal authentication and post mock
        response registered, although the test may replace them, if needed.
        """
        super(TestCsrRestPreSharedKeyCreate, self).setUp(host,
                                                         tunnel_ip,
                                                         timeout)
        self._helper_register_auth_request()
        self._helper_register_psk_post(5)

    def _helper_register_psk_get(self, override=None):
        content = {u'kind': u'object#ike-keyring',
                   u'keyring-name': u'5',
                   u'pre-shared-key-list': [
                       {u'key': u'super-secret',
                        u'encrypted': False,
                        u'peer-address': u'10.10.10.20 255.255.255.0'}
                   ]}
        if override:
            content.update(override)
        self._register_local_get(URI_PSK_ID % '5', json=content)

    def test_create_delete_pre_shared_key(self):
        """Create and then delete a keyring entry for pre-shared key."""
        psk_info = {u'keyring-name': u'5',
                    u'pre-shared-key-list': [
                        {u'key': u'super-secret',
                         u'encrypted': False,
                         u'peer-address': u'10.10.10.20/24'}
                    ]}
        location = self.csr.create_pre_shared_key(psk_info)
        self.assertEqual(requests.codes.CREATED, self.csr.status)
        self.assertIn(URI_PSK_ID % '5', location)

        # Check the hard-coded items that get set as well...
        self._helper_register_psk_get()
        content = self.csr.get_request(location, full_url=True)
        self.assertEqual(requests.codes.OK, self.csr.status)
        expected_policy = {u'kind': u'object#ike-keyring'}
        expected_policy.update(psk_info)
        # Note: the peer CIDR is returned as an IP and mask
        expected_policy[u'pre-shared-key-list'][0][u'peer-address'] = (
            u'10.10.10.20 255.255.255.0')
        self.assertEqual(expected_policy, content)

        # Now delete and verify pre-shared key is gone
        self._register_local_delete(URI_PSK, 5)
        self._register_local_get_not_found(URI_PSK, 5)

        self.csr.delete_pre_shared_key('5')
        self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)
        content = self.csr.get_request(location, full_url=True)
        self.assertEqual(requests.codes.NOT_FOUND, self.csr.status)

    def test_create_pre_shared_key_with_fqdn_peer(self):
        """Create pre-shared key using FQDN for peer address."""
        psk_info = {u'keyring-name': u'5',
                    u'pre-shared-key-list': [
                        {u'key': u'super-secret',
                         u'encrypted': False,
                         u'peer-address': u'cisco.com'}
                    ]}
        location = self.csr.create_pre_shared_key(psk_info)
        self.assertEqual(requests.codes.CREATED, self.csr.status)
        self.assertIn(URI_PSK_ID % '5', location)

        # Check the hard-coded items that get set as well...
        self._helper_register_psk_get(
            override={u'pre-shared-key-list': [
                          {u'key': u'super-secret',
                           u'encrypted': False,
                           u'peer-address': u'cisco.com'}
                      ]}
        )
        content = self.csr.get_request(location, full_url=True)
        self.assertEqual(requests.codes.OK, self.csr.status)
        expected_policy = {u'kind': u'object#ike-keyring'}
        expected_policy.update(psk_info)
        self.assertEqual(expected_policy, content)


class TestCsrRestIPSecConnectionCreate(CiscoCsrBaseTestCase):

    """Test IPSec site-to-site connection REST requests.

    This requires us to have first created an IKE policy, IPSec policy,
    and pre-shared key, so it's more of an itegration test, when used
    with a real CSR (as we can't mock out these pre-conditions).
    """

    def setUp(self, host='localhost', tunnel_ip='10.10.10.10', timeout=None):
        """Setup for each test in this suite.

        Each test case will have a normal authentication mock response
        registered here, although they may replace it, as needed.
        """
        super(TestCsrRestIPSecConnectionCreate, self).setUp(host,
                                                            tunnel_ip,
                                                            timeout)
        self._helper_register_auth_request()
        self.route_id = '10.1.0.0_24_GigabitEthernet1'

    def _make_psk_for_test(self):
        psk_id = generate_pre_shared_key_id()
        self._remove_resource_for_test(self.csr.delete_pre_shared_key,
                                       psk_id)
        self._helper_register_psk_post(psk_id)
        psk_info = {u'keyring-name': u'%d' % psk_id,
                    u'pre-shared-key-list': [
                        {u'key': u'super-secret',
                         u'encrypted': False,
                         u'peer-address': u'10.10.10.20/24'}
                    ]}
        self.csr.create_pre_shared_key(psk_info)
        if self.csr.status != requests.codes.CREATED:
            self.fail("Unable to create PSK for test case")
        self.addCleanup(self._remove_resource_for_test,
                        self.csr.delete_pre_shared_key, psk_id)
        return psk_id

    def _make_ike_policy_for_test(self):
        policy_id = generate_ike_policy_id()
        self._remove_resource_for_test(self.csr.delete_ike_policy,
                                       policy_id)
        self._helper_register_ike_policy_post(policy_id)
        policy_info = {u'priority-id': u'%d' % policy_id,
                       u'encryption': u'aes',
                       u'hash': u'sha',
                       u'dhGroup': 5,
                       u'lifetime': 3600}
        self.csr.create_ike_policy(policy_info)
        if self.csr.status != requests.codes.CREATED:
            self.fail("Unable to create IKE policy for test case")
        self.addCleanup(self._remove_resource_for_test,
                        self.csr.delete_ike_policy, policy_id)
        return policy_id

    def _make_ipsec_policy_for_test(self):
        policy_id = generate_ipsec_policy_id()
        self._remove_resource_for_test(self.csr.delete_ipsec_policy,
                                       policy_id)
        self._helper_register_ipsec_policy_post(policy_id)
        policy_info = {
            u'policy-id': u'%d' % policy_id,
            u'protection-suite': {
                u'esp-encryption': u'esp-aes',
                u'esp-authentication': u'esp-sha-hmac',
                u'ah': u'ah-sha-hmac',
            },
            u'lifetime-sec': 120,
            u'pfs': u'group5',
            u'anti-replay-window-size': u'disable'
        }
        self.csr.create_ipsec_policy(policy_info)
        if self.csr.status != requests.codes.CREATED:
            self.fail("Unable to create IPSec policy for test case")
        self.addCleanup(self._remove_resource_for_test,
                        self.csr.delete_ipsec_policy, policy_id)
        return policy_id

    def _remove_resource_for_test(self, delete_resource, resource_id):
        self._register_local_delete_by_id(resource_id)
        delete_resource(resource_id)

    def _prepare_for_site_conn_create(self, skip_psk=False, skip_ike=False,
                                      skip_ipsec=False):
        """Create the policies and PSK so can then create site conn."""
        if not skip_psk:
            ike_policy_id = self._make_psk_for_test()
        else:
            ike_policy_id = generate_ike_policy_id()
        if not skip_ike:
            self._make_ike_policy_for_test()
        if not skip_ipsec:
            ipsec_policy_id = self._make_ipsec_policy_for_test()
        else:
            ipsec_policy_id = generate_ipsec_policy_id()
        # Note: Use same ID number for tunnel and IPSec policy, so that when
        # GET tunnel info, the mocks can infer the IPSec policy ID from the
        # tunnel number.
        return (ike_policy_id, ipsec_policy_id, ipsec_policy_id)

    def _helper_register_ipsec_conn_get(self, tunnel, override=None):
        # Use same number, to allow mock to generate IPSec policy ID
        ipsec_policy_id = tunnel[6:]
        content = {u'kind': u'object#vpn-site-to-site',
                   u'vpn-interface-name': u'%s' % tunnel,
                   u'ip-version': u'ipv4',
                   u'vpn-type': u'site-to-site',
                   u'ipsec-policy-id': u'%s' % ipsec_policy_id,
                   u'ike-profile-id': None,
                   u'mtu': 1500,
                   u'local-device': {
                       u'ip-address': '10.3.0.1/24',
                       u'tunnel-ip-address': '10.10.10.10'
                   },
                   u'remote-device': {
                       u'tunnel-ip-address': '10.10.10.20'
                   }}
        if override:
            content.update(override)
        self._register_local_get(URI_IPSEC_CONN_ID % tunnel, json=content)

    def test_create_delete_ipsec_connection(self):
        """Create and then delete an IPSec connection."""
        ike_policy_id, ipsec_policy_id, tunnel_id = (
            self._prepare_for_site_conn_create())
        tunnel_name = u'Tunnel%s' % tunnel_id
        self._helper_register_tunnel_post(tunnel_name)
        self._register_local_post(URI_ROUTES, self.route_id)
        connection_info = {
            u'vpn-interface-name': tunnel_name,
            u'ipsec-policy-id': u'%d' % ipsec_policy_id,
            u'mtu': 1500,
            u'local-device': {u'ip-address': u'10.3.0.1/24',
                              u'tunnel-ip-address': u'10.10.10.10'},
            u'remote-device': {u'tunnel-ip-address': u'10.10.10.20'}
        }
        expected_connection = {u'kind': u'object#vpn-site-to-site',
                               u'ike-profile-id': None,
                               u'vpn-type': u'site-to-site',
                               u'mtu': 1500,
                               u'ip-version': u'ipv4'}
        expected_connection.update(connection_info)
        location = self.csr.create_ipsec_connection(connection_info)
        self.addCleanup(self._remove_resource_for_test,
                        self.csr.delete_ipsec_connection,
                        tunnel_name)
        self.assertEqual(requests.codes.CREATED, self.csr.status)
        self.assertIn(URI_IPSEC_CONN_ID % tunnel_name, location)

        # Check the hard-coded items that get set as well...
        self._helper_register_ipsec_conn_get(tunnel_name)
        content = self.csr.get_request(location, full_url=True)
        self.assertEqual(requests.codes.OK, self.csr.status)
        self.assertEqual(expected_connection, content)

        # Now delete and verify that site-to-site connection is gone
        self._register_local_delete_by_id(tunnel_name)
        self._register_local_delete_by_id(ipsec_policy_id)
        self._register_local_delete_by_id(ike_policy_id)
        self._register_local_get_not_found(URI_IPSEC_CONN,
                                           tunnel_name)
        # Only delete connection. Cleanup will take care of prerequisites
        self.csr.delete_ipsec_connection(tunnel_name)
        self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)
        content = self.csr.get_request(location, full_url=True)
        self.assertEqual(requests.codes.NOT_FOUND, self.csr.status)

    def test_create_ipsec_connection_with_no_tunnel_subnet(self):
        """Create an IPSec connection without an IP address on tunnel."""
        _, ipsec_policy_id, tunnel_id = (
            self._prepare_for_site_conn_create())
        tunnel_name = u'Tunnel%s' % tunnel_id
        self._helper_register_tunnel_post(tunnel_name)
        self._register_local_post(URI_ROUTES, self.route_id)
        connection_info = {
            u'vpn-interface-name': tunnel_name,
            u'ipsec-policy-id': u'%d' % ipsec_policy_id,
            u'local-device': {u'ip-address': u'GigabitEthernet3',
                              u'tunnel-ip-address': u'10.10.10.10'},
            u'remote-device': {u'tunnel-ip-address': u'10.10.10.20'}
        }
        expected_connection = {u'kind': u'object#vpn-site-to-site',
                               u'ike-profile-id': None,
                               u'vpn-type': u'site-to-site',
                               u'mtu': 1500,
                               u'ip-version': u'ipv4'}
        expected_connection.update(connection_info)
        location = self.csr.create_ipsec_connection(connection_info)
        self.addCleanup(self._remove_resource_for_test,
                        self.csr.delete_ipsec_connection,
                        tunnel_name)
        self.assertEqual(requests.codes.CREATED, self.csr.status)
        self.assertIn('vpn-svc/site-to-site/' + tunnel_name, location)

        # Check the hard-coded items that get set as well...
        self._helper_register_ipsec_conn_get(tunnel_name, override={
            u'local-device': {
                u'ip-address': u'GigabitEthernet3',
                u'tunnel-ip-address': u'10.10.10.10'
            }})
        content = self.csr.get_request(location, full_url=True)
        self.assertEqual(requests.codes.OK, self.csr.status)
        self.assertEqual(expected_connection, content)

    def test_create_ipsec_connection_no_pre_shared_key(self):
        """Test of connection create without associated pre-shared key.

        The CSR will create the connection, but will not be able to pass
        traffic without the pre-shared key.
        """

        _, ipsec_policy_id, tunnel_id = (
            self._prepare_for_site_conn_create(skip_psk=True))
        tunnel_name = u'Tunnel%s' % tunnel_id
        self._helper_register_tunnel_post(tunnel_name)
        self._register_local_post(URI_ROUTES, self.route_id)
        connection_info = {
            u'vpn-interface-name': tunnel_name,
            u'ipsec-policy-id': u'%d' % ipsec_policy_id,
            u'mtu': 1500,
            u'local-device': {u'ip-address': u'10.3.0.1/24',
                              u'tunnel-ip-address': u'10.10.10.10'},
            u'remote-device': {u'tunnel-ip-address': u'10.10.10.20'}
        }
        expected_connection = {u'kind': u'object#vpn-site-to-site',
                               u'ike-profile-id': None,
                               u'vpn-type': u'site-to-site',
                               u'ip-version': u'ipv4'}
        expected_connection.update(connection_info)
        location = self.csr.create_ipsec_connection(connection_info)
        self.addCleanup(self._remove_resource_for_test,
                        self.csr.delete_ipsec_connection,
                        tunnel_name)
        self.assertEqual(requests.codes.CREATED, self.csr.status)
        self.assertIn(URI_IPSEC_CONN_ID % tunnel_name, location)

        # Check the hard-coded items that get set as well...
        self._helper_register_ipsec_conn_get(tunnel_name)
        content = self.csr.get_request(location, full_url=True)
        self.assertEqual(requests.codes.OK, self.csr.status)
        self.assertEqual(expected_connection, content)

    def test_create_ipsec_connection_with_default_ike_policy(self):
        """Test of connection create without IKE policy (uses default).

        Without an IKE policy, the CSR will use a built-in default IKE
        policy setting for the connection.
        """

        _, ipsec_policy_id, tunnel_id = (
            self._prepare_for_site_conn_create(skip_ike=True))
        tunnel_name = u'Tunnel%s' % tunnel_id
        self._helper_register_tunnel_post(tunnel_name)
        self._register_local_post(URI_ROUTES, self.route_id)
        connection_info = {
            u'vpn-interface-name': tunnel_name,
            u'ipsec-policy-id': u'%d' % ipsec_policy_id,
            u'mtu': 1500,
            u'local-device': {u'ip-address': u'10.3.0.1/24',
                              u'tunnel-ip-address': u'10.10.10.10'},
            u'remote-device': {u'tunnel-ip-address': u'10.10.10.20'}
        }
        expected_connection = {u'kind': u'object#vpn-site-to-site',
                               u'ike-profile-id': None,
                               u'vpn-type': u'site-to-site',
                               u'ip-version': u'ipv4'}
        expected_connection.update(connection_info)
        location = self.csr.create_ipsec_connection(connection_info)
        self.addCleanup(self._remove_resource_for_test,
                        self.csr.delete_ipsec_connection,
                        tunnel_name)
        self.assertEqual(requests.codes.CREATED, self.csr.status)
        self.assertIn(URI_IPSEC_CONN_ID % tunnel_name, location)

        # Check the hard-coded items that get set as well...
        self._helper_register_ipsec_conn_get(tunnel_name)
        content = self.csr.get_request(location, full_url=True)
        self.assertEqual(requests.codes.OK, self.csr.status)
        self.assertEqual(expected_connection, content)

    def test_set_ipsec_connection_admin_state_changes(self):
        """Create IPSec connection in admin down state."""
        _, ipsec_policy_id, tunnel_id = (
            self._prepare_for_site_conn_create())
        tunnel_name = u'Tunnel%s' % tunnel_id
        self._helper_register_tunnel_post(tunnel_name)
        self._register_local_post(URI_ROUTES, self.route_id)
        connection_info = {
            u'vpn-interface-name': tunnel_name,
            u'ipsec-policy-id': u'%d' % ipsec_policy_id,
            u'mtu': 1500,
            u'local-device': {u'ip-address': u'10.3.0.1/24',
                              u'tunnel-ip-address': u'10.10.10.10'},
            u'remote-device': {u'tunnel-ip-address': u'10.10.10.20'}
        }
        location = self.csr.create_ipsec_connection(connection_info)
        self.addCleanup(self._remove_resource_for_test,
                        self.csr.delete_ipsec_connection,
                        tunnel_name)
        self.assertEqual(requests.codes.CREATED, self.csr.status)
        self.assertIn(URI_IPSEC_CONN_ID % tunnel_name, location)

        state_url = location + "/state"
        state_uri = URI_IPSEC_CONN_ID % tunnel_name + '/state'
        # Note: When created, the tunnel will be in admin 'up' state
        # Note: Line protocol state will be down, unless have an active conn.
        expected_state = {u'kind': u'object#vpn-site-to-site-state',
                          u'vpn-interface-name': tunnel_name,
                          u'line-protocol-state': u'down',
                          u'enabled': False}
        self._register_local_put(URI_IPSEC_CONN_ID % tunnel_name, 'state')
        self.csr.set_ipsec_connection_state(tunnel_name, admin_up=False)
        self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)

        self._register_local_get(state_uri, json=expected_state)
        content = self.csr.get_request(state_url, full_url=True)
        self.assertEqual(requests.codes.OK, self.csr.status)
        self.assertEqual(expected_state, content)

        self.csr.set_ipsec_connection_state(tunnel_name, admin_up=True)
        self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)
        expected_state = {u'kind': u'object#vpn-site-to-site-state',
                          u'vpn-interface-name': tunnel_name,
                          u'line-protocol-state': u'down',
                          u'enabled': True}
        self._register_local_get(state_uri, json=expected_state)
        content = self.csr.get_request(state_url, full_url=True)
        self.assertEqual(requests.codes.OK, self.csr.status)
        self.assertEqual(expected_state, content)

    def test_create_ipsec_connection_missing_ipsec_policy(self):
        """Negative test of connection create without IPSec policy."""
        _, ipsec_policy_id, tunnel_id = (
            self._prepare_for_site_conn_create(skip_ipsec=True))
        tunnel_name = u'Tunnel%s' % tunnel_id
        self._register_local_post(URI_IPSEC_CONN, tunnel_name,
                                  result_code=requests.codes.BAD_REQUEST)
        connection_info = {
            u'vpn-interface-name': tunnel_name,
            u'ipsec-policy-id': u'%d' % ipsec_policy_id,
            u'local-device': {u'ip-address': u'10.3.0.1/24',
                              u'tunnel-ip-address': u'10.10.10.10'},
            u'remote-device': {u'tunnel-ip-address': u'10.10.10.20'}
        }
        self.csr.create_ipsec_connection(connection_info)
        self.addCleanup(self._remove_resource_for_test,
                        self.csr.delete_ipsec_connection,
                        'Tunnel%d' % tunnel_id)
        self.assertEqual(requests.codes.BAD_REQUEST, self.csr.status)

    def _determine_conflicting_ip(self):
        content = {u'kind': u'object#interface',
                   u'subnet-mask': u'255.255.255.0',
                   u'ip-address': u'10.5.0.2'}
        self._register_local_get('interfaces/GigabitEthernet3', json=content)
        details = self.csr.get_request('interfaces/GigabitEthernet3')
        if self.csr.status != requests.codes.OK:
            self.fail("Unable to obtain interface GigabitEthernet3's IP")
        if_ip = details.get('ip-address')
        if not if_ip:
            self.fail("No IP address for GigabitEthernet3 interface")
        return '.'.join(if_ip.split('.')[:3]) + '.10'

    def test_create_ipsec_connection_conficting_tunnel_ip(self):
        """Negative test of connection create with conflicting tunnel IP.

        Find out the IP of a local interface (GigabitEthernet3) and create an
        IP that is on the same subnet. Note: this interface needs to be up.
        """

        conflicting_ip = self._determine_conflicting_ip()
        _, ipsec_policy_id, tunnel_id = (
            self._prepare_for_site_conn_create())
        tunnel_name = u'Tunnel%s' % tunnel_id
        self._register_local_post(URI_IPSEC_CONN, tunnel_name,
                                  result_code=requests.codes.BAD_REQUEST)
        connection_info = {
            u'vpn-interface-name': tunnel_name,
            u'ipsec-policy-id': u'%d' % ipsec_policy_id,
            u'local-device': {u'ip-address': u'%s/24' % conflicting_ip,
                              u'tunnel-ip-address': u'10.10.10.10'},
            u'remote-device': {u'tunnel-ip-address': u'10.10.10.20'}
        }
        self.csr.create_ipsec_connection(connection_info)
        self.addCleanup(self._remove_resource_for_test,
                        self.csr.delete_ipsec_connection,
                        tunnel_name)
        self.assertEqual(requests.codes.BAD_REQUEST, self.csr.status)

    def test_create_ipsec_connection_with_max_mtu(self):
        """Create an IPSec connection with max MTU value."""
        _, ipsec_policy_id, tunnel_id = (
            self._prepare_for_site_conn_create())
        tunnel_name = u'Tunnel%s' % tunnel_id
        self._helper_register_tunnel_post(tunnel_name)
        self._register_local_post(URI_ROUTES, self.route_id)
        connection_info = {
            u'vpn-interface-name': tunnel_name,
            u'ipsec-policy-id': u'%d' % ipsec_policy_id,
            u'mtu': 9192,
            u'local-device': {u'ip-address': u'10.3.0.1/24',
                              u'tunnel-ip-address': u'10.10.10.10'},
            u'remote-device': {u'tunnel-ip-address': u'10.10.10.20'}
        }
        expected_connection = {u'kind': u'object#vpn-site-to-site',
                               u'ike-profile-id': None,
                               u'vpn-type': u'site-to-site',
                               u'ip-version': u'ipv4'}
        expected_connection.update(connection_info)
        location = self.csr.create_ipsec_connection(connection_info)
        self.addCleanup(self._remove_resource_for_test,
                        self.csr.delete_ipsec_connection,
                        tunnel_name)
        self.assertEqual(requests.codes.CREATED, self.csr.status)
        self.assertIn(URI_IPSEC_CONN_ID % tunnel_name, location)

        # Check the hard-coded items that get set as well...
        self._helper_register_ipsec_conn_get(tunnel_name, override={
            u'mtu': 9192})
        content = self.csr.get_request(location, full_url=True)
        self.assertEqual(requests.codes.OK, self.csr.status)
        self.assertEqual(expected_connection, content)

    def test_create_ipsec_connection_with_bad_mtu(self):
        """Negative test of connection create with unsupported MTU value."""
        _, ipsec_policy_id, tunnel_id = (
            self._prepare_for_site_conn_create())
        tunnel_name = u'Tunnel%s' % tunnel_id
        self._register_local_post(URI_IPSEC_CONN, tunnel_name,
                                  result_code=requests.codes.BAD_REQUEST)
        connection_info = {
            u'vpn-interface-name': tunnel_name,
            u'ipsec-policy-id': u'%d' % ipsec_policy_id,
            u'mtu': 9193,
            u'local-device': {u'ip-address': u'10.3.0.1/24',
                              u'tunnel-ip-address': u'10.10.10.10'},
            u'remote-device': {u'tunnel-ip-address': u'10.10.10.20'}
        }
        self.csr.create_ipsec_connection(connection_info)
        self.addCleanup(self._remove_resource_for_test,
                        self.csr.delete_ipsec_connection,
                        tunnel_name)
        self.assertEqual(requests.codes.BAD_REQUEST, self.csr.status)

    def test_status_when_no_tunnels_exist(self):
        """Get status, when there are no tunnels."""
        content = {u'kind': u'collection#vpn-active-sessions',
                   u'items': []}
        self._register_local_get(URI_SESSIONS, json=content)
        tunnels = self.csr.read_tunnel_statuses()
        self.assertEqual(requests.codes.OK, self.csr.status)
        self.assertEqual([], tunnels)

    def test_status_for_one_tunnel(self):
        """Get status of one tunnel."""
        # Create the IPsec site-to-site connection first
        _, ipsec_policy_id, tunnel_id = (
            self._prepare_for_site_conn_create())
        tunnel_name = u'Tunnel%s' % tunnel_id
        self._helper_register_tunnel_post(tunnel_name)
        self._register_local_post(URI_ROUTES, self.route_id)
        connection_info = {
            u'vpn-interface-name': tunnel_name,
            u'ipsec-policy-id': u'%d' % ipsec_policy_id,
            u'local-device': {u'ip-address': u'10.3.0.1/24',
                              u'tunnel-ip-address': u'10.10.10.10'},
            u'remote-device': {u'tunnel-ip-address': u'10.10.10.20'}
        }
        location = self.csr.create_ipsec_connection(connection_info)
        self.addCleanup(self._remove_resource_for_test,
                        self.csr.delete_ipsec_connection,
                        tunnel_name)
        self.assertEqual(requests.codes.CREATED, self.csr.status)
        self.assertIn(URI_IPSEC_CONN_ID % tunnel_name, location)

        # Now, check the status
        content = {u'kind': u'collection#vpn-active-sessions',
                   u'items': [{u'status': u'DOWN-NEGOTIATING',
                               u'vpn-interface-name': tunnel_name}, ]}
        self._register_local_get(URI_SESSIONS, json=content)
        self._helper_register_ipsec_conn_get(tunnel_name)
        tunnels = self.csr.read_tunnel_statuses()
        self.assertEqual(requests.codes.OK, self.csr.status)
        self.assertEqual([(tunnel_name, u'DOWN-NEGOTIATING'), ], tunnels)


class TestCsrRestIkeKeepaliveCreate(CiscoCsrBaseTestCase):

    """Test IKE keepalive REST requests.

    Note: On the Cisco CSR, the IKE keepalive for v1 is a global configuration
    that applies to all VPN tunnels to specify Dead Peer Detection information.
    As a result, this REST API is not used in the OpenStack device driver, and
    the keepalive will default to zero (disabled).
    """

    def _save_dpd_info(self):
        details = self.csr.get_request(URI_KEEPALIVE)
        if self.csr.status == requests.codes.OK:
            self.dpd = details
            self.addCleanup(self._restore_dpd_info)
        elif self.csr.status != requests.codes.NOT_FOUND:
            self.fail("Unable to save original DPD info")

    def _restore_dpd_info(self):
        payload = {'interval': self.dpd['interval'],
                   'retry': self.dpd['retry']}
        self.csr.put_request(URI_KEEPALIVE, payload=payload)
        if self.csr.status != requests.codes.NO_CONTENT:
            self.fail("Unable to restore DPD info after test")

    def setUp(self, host='localhost', tunnel_ip='10.10.10.10', timeout=None):
        """Set up for each test in this suite.

        Each test case will have a normal authentication, get, and put mock
        responses registered, although the test may replace them, if needed.
        Dead Peer Detection settions will be saved for each test, and
        restored afterwards.
        """
        super(TestCsrRestIkeKeepaliveCreate, self).setUp(host,
                                                         tunnel_ip,
                                                         timeout)
        self._helper_register_auth_request()
        self._helper_register_keepalive_get()
        self._register_local_put('vpn-svc/ike', 'keepalive')
        self._save_dpd_info()
        self.csr.token = None

    def _helper_register_keepalive_get(self, override=None):
        content = {u'interval': 60,
                   u'retry': 4,
                   u'periodic': True}
        if override:
            content.update(override)
        self._register_local_get(URI_KEEPALIVE, json=content)

    def test_configure_ike_keepalive(self):
        """Set IKE keep-alive (aka Dead Peer Detection) for the CSR."""
        keepalive_info = {'interval': 60, 'retry': 4}
        self.csr.configure_ike_keepalive(keepalive_info)
        self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)
        content = self.csr.get_request(URI_KEEPALIVE)
        self.assertEqual(requests.codes.OK, self.csr.status)
        expected = {'periodic': False}
        expected.update(keepalive_info)
        self.assertDictSupersetOf(expected, content)

    def test_disable_ike_keepalive(self):
        """Disable IKE keep-alive (aka Dead Peer Detection) for the CSR."""
        keepalive_info = {'interval': 0, 'retry': 4}
        self.csr.configure_ike_keepalive(keepalive_info)
        self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)


class TestCsrRestStaticRoute(CiscoCsrBaseTestCase):

    """Test static route REST requests.

    A static route is added for the peer's private network. Would create
    a route for each of the peer CIDRs specified for the VPN connection.
    """

    def setUp(self, host='localhost', tunnel_ip='10.10.10.10', timeout=None):
        """Set up for each test in this suite.

        Each test case will have a normal authentication mock response
        registered, although the test may replace it, if needed.
        """
        super(TestCsrRestStaticRoute, self).setUp(host, tunnel_ip, timeout)
        self._helper_register_auth_request()

    def test_create_delete_static_route(self):
        """Create and then delete a static route for the tunnel."""
        expected_id = '10.1.0.0_24_GigabitEthernet1'
        self._register_local_post(URI_ROUTES, resource_id=expected_id)
        cidr = u'10.1.0.0/24'
        interface = u'GigabitEthernet1'
        route_info = {u'destination-network': cidr,
                      u'outgoing-interface': interface}
        location = self.csr.create_static_route(route_info)
        self.assertEqual(requests.codes.CREATED, self.csr.status)
        self.assertIn(URI_ROUTES_ID % expected_id, location)

        # Check the hard-coded items that get set as well...
        expected_route = {u'destination-network': u'10.1.0.0/24',
                          u'kind': u'object#static-route',
                          u'next-hop-router': None,
                          u'outgoing-interface': u'GigabitEthernet1',
                          u'admin-distance': 1}
        self._register_local_get(URI_ROUTES_ID % expected_id,
                                 json=expected_route)
        content = self.csr.get_request(location, full_url=True)
        self.assertEqual(requests.codes.OK, self.csr.status)
        self.assertEqual(expected_route, content)

        # Now delete and verify that static route is gone
        self._register_local_delete(URI_ROUTES, expected_id)
        self._register_local_get_not_found(URI_ROUTES, expected_id)
        route_id = csr_client.make_route_id(cidr, interface)
        self.csr.delete_static_route(route_id)
        self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)
        content = self.csr.get_request(location, full_url=True)
        self.assertEqual(requests.codes.NOT_FOUND, self.csr.status)
