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
# @author: Paul Michali, Cisco Systems, Inc.

#TODO(pcm): Rename this file to remove the "no" prefix, once httmock is
# approved and added to requirements.txt

import random

# TODO(pcm): Remove when update to requests-mock package. Comment out, if use
# local copy of httmock.py source. Needed for PEP8.
import httmock
import requests

from neutron.openstack.common import log as logging
from neutron.services.vpn.device_drivers import (
    cisco_csr_rest_client as csr_client)
from neutron.tests import base
from neutron.tests.unit.services.vpn.device_drivers import (
    cisco_csr_mock as csr_request)
# TODO(pcm) Uncomment to run w/local copy of httmock.py source. Remove when
# update to requests-mock package.
# from neutron.tests.unit.services.vpn.device_drivers import httmock


LOG = logging.getLogger(__name__)
# Enables debug logging to console
if True:
    logging.CONF.set_override('debug', True)
    logging.setup('neutron')

dummy_policy_id = 'dummy-ipsec-policy-id-name'


# Note: Helper functions to test reuse of IDs.
def generate_pre_shared_key_id():
    return random.randint(100, 200)


def generate_ike_policy_id():
    return random.randint(200, 300)


def generate_ipsec_policy_id():
    return random.randint(300, 400)


class TestCsrLoginRestApi(base.BaseTestCase):

    """Test logging into CSR to obtain token-id."""

    def setUp(self, host='localhost', tunnel_ip='10.10.10.10', timeout=None):
        super(TestCsrLoginRestApi, self).setUp()
        info = {'rest_mgmt_ip': host, 'tunnel_ip': tunnel_ip,
                'username': 'stack', 'password': 'cisco', 'timeout': timeout}
        self.csr = csr_client.CsrRestClient(info)

    def test_get_token(self):
        """Obtain the token and its expiration time."""
        with httmock.HTTMock(csr_request.token):
            self.assertTrue(self.csr.authenticate())
            self.assertEqual(requests.codes.OK, self.csr.status)
            self.assertIsNotNone(self.csr.token)

    def test_unauthorized_token_request(self):
        """Negative test of invalid user/password."""
        self.csr.auth = ('stack', 'bogus')
        with httmock.HTTMock(csr_request.token_unauthorized):
            self.assertIsNone(self.csr.authenticate())
            self.assertEqual(requests.codes.UNAUTHORIZED, self.csr.status)

    def test_non_existent_host(self):
        """Negative test of request to non-existent host."""
        self.csr.host = 'wrong-host'
        self.csr.token = 'Set by some previously successful access'
        with httmock.HTTMock(csr_request.token_wrong_host):
            self.assertIsNone(self.csr.authenticate())
            self.assertEqual(requests.codes.NOT_FOUND, self.csr.status)
            self.assertIsNone(self.csr.token)

    def test_timeout_on_token_access(self):
        """Negative test of a timeout on a request."""
        with httmock.HTTMock(csr_request.token_timeout):
            self.assertIsNone(self.csr.authenticate())
            self.assertEqual(requests.codes.REQUEST_TIMEOUT, self.csr.status)
            self.assertIsNone(self.csr.token)


class TestCsrGetRestApi(base.BaseTestCase):

    """Test CSR GET REST API."""

    def setUp(self, host='localhost', tunnel_ip='10.10.10.10', timeout=None):
        super(TestCsrGetRestApi, self).setUp()
        info = {'rest_mgmt_ip': host, 'tunnel_ip': tunnel_ip,
                'username': 'stack', 'password': 'cisco', 'timeout': timeout}
        self.csr = csr_client.CsrRestClient(info)

    def test_valid_rest_gets(self):
        """Simple GET requests.

        First request will do a post to get token (login). Assumes
        that there are two interfaces on the CSR.
        """

        with httmock.HTTMock(csr_request.token,
                             csr_request.normal_get):
            content = self.csr.get_request('global/host-name')
            self.assertEqual(requests.codes.OK, self.csr.status)
            self.assertIn('host-name', content)
            self.assertNotEqual(None, content['host-name'])

            content = self.csr.get_request('global/local-users')
            self.assertEqual(requests.codes.OK, self.csr.status)
            self.assertIn('users', content)


class TestCsrPostRestApi(base.BaseTestCase):

    """Test CSR POST REST API."""

    def setUp(self, host='localhost', tunnel_ip='10.10.10.10', timeout=None):
        super(TestCsrPostRestApi, self).setUp()
        info = {'rest_mgmt_ip': host, 'tunnel_ip': tunnel_ip,
                'username': 'stack', 'password': 'cisco', 'timeout': timeout}
        self.csr = csr_client.CsrRestClient(info)

    def test_post_requests(self):
        """Simple POST requests (repeatable).

        First request will do a post to get token (login). Assumes
        that there are two interfaces (Ge1 and Ge2) on the CSR.
        """

        with httmock.HTTMock(csr_request.token,
                             csr_request.post):
            content = self.csr.post_request(
                'interfaces/GigabitEthernet1/statistics',
                payload={'action': 'clear'})
            self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)
            self.assertIsNone(content)
            content = self.csr.post_request(
                'interfaces/GigabitEthernet2/statistics',
                payload={'action': 'clear'})
            self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)
            self.assertIsNone(content)

    def test_post_with_location(self):
        """Create a user and verify that location returned."""
        with httmock.HTTMock(csr_request.token,
                             csr_request.post):
            location = self.csr.post_request(
                'global/local-users',
                payload={'username': 'test-user',
                         'password': 'pass12345',
                         'privilege': 15})
            self.assertEqual(requests.codes.CREATED, self.csr.status)
            self.assertIn('global/local-users/test-user', location)

    def test_post_missing_required_attribute(self):
        """Negative test of POST with missing mandatory info."""
        with httmock.HTTMock(csr_request.token,
                             csr_request.post):
            self.csr.post_request('global/local-users',
                                  payload={'password': 'pass12345',
                                           'privilege': 15})
            self.assertEqual(requests.codes.BAD_REQUEST, self.csr.status)

    def test_post_invalid_attribute(self):
        """Negative test of POST with invalid info."""
        with httmock.HTTMock(csr_request.token,
                             csr_request.post):
            self.csr.post_request('global/local-users',
                                  payload={'username': 'test-user',
                                           'password': 'pass12345',
                                           'privilege': 20})
            self.assertEqual(requests.codes.BAD_REQUEST, self.csr.status)

    def test_post_already_exists(self):
        """Negative test of a duplicate POST.

        Uses the lower level _do_request() API to just perform the POST and
        obtain the response, without any error processing.
        """
        with httmock.HTTMock(csr_request.token,
                             csr_request.post):
                location = self.csr._do_request(
                    'POST',
                    'global/local-users',
                    payload={'username': 'test-user',
                             'password': 'pass12345',
                             'privilege': 15},
                    more_headers=csr_client.HEADER_CONTENT_TYPE_JSON)
                self.assertEqual(requests.codes.CREATED, self.csr.status)
                self.assertIn('global/local-users/test-user', location)
        with httmock.HTTMock(csr_request.token,
                             csr_request.post_change_attempt):
                self.csr._do_request(
                    'POST',
                    'global/local-users',
                    payload={'username': 'test-user',
                             'password': 'pass12345',
                             'privilege': 15},
                    more_headers=csr_client.HEADER_CONTENT_TYPE_JSON)
                # Note: For local-user, a 404 error is returned. For
                # site-to-site connection a 400 is returned.
                self.assertEqual(requests.codes.NOT_FOUND, self.csr.status)

    def test_post_changing_value(self):
        """Negative test of a POST trying to change a value."""
        with httmock.HTTMock(csr_request.token,
                             csr_request.post):
            location = self.csr.post_request(
                'global/local-users',
                payload={'username': 'test-user',
                         'password': 'pass12345',
                         'privilege': 15})
            self.assertEqual(requests.codes.CREATED, self.csr.status)
            self.assertIn('global/local-users/test-user', location)
        with httmock.HTTMock(csr_request.token,
                             csr_request.post_change_attempt):
            content = self.csr.post_request('global/local-users',
                                            payload={'username': 'test-user',
                                                     'password': 'changed',
                                                     'privilege': 15})
            self.assertEqual(requests.codes.NOT_FOUND, self.csr.status)
            expected = {u'error-code': -1,
                        u'error-message': u'user test-user already exists'}
            self.assertDictContainsSubset(expected, content)


class TestCsrPutRestApi(base.BaseTestCase):

    """Test CSR PUT REST API."""

    def _save_resources(self):
        with httmock.HTTMock(csr_request.token,
                             csr_request.normal_get):
            details = self.csr.get_request('global/host-name')
            if self.csr.status != requests.codes.OK:
                self.fail("Unable to save original host name")
            self.original_host = details['host-name']
            details = self.csr.get_request('interfaces/GigabitEthernet1')
            if self.csr.status != requests.codes.OK:
                self.fail("Unable to save interface Ge1 description")
            self.original_if = details
            if details.get('description', ''):
                self.original_if['description'] = ''
            self.csr.token = None

    def _restore_resources(self, user, password):
        """Restore the host name and itnerface description.

        Must restore the user and password, so that authentication
        token can be obtained (as some tests corrupt auth info).
        Will also clear token, so that it gets a fresh token.
        """

        self.csr.auth = (user, password)
        self.csr.token = None
        with httmock.HTTMock(csr_request.token,
                             csr_request.put):
            payload = {'host-name': self.original_host}
            self.csr.put_request('global/host-name', payload=payload)
            if self.csr.status != requests.codes.NO_CONTENT:
                self.fail("Unable to restore host name after test")
            payload = {'description': self.original_if['description'],
                       'if-name': self.original_if['if-name'],
                       'ip-address': self.original_if['ip-address'],
                       'subnet-mask': self.original_if['subnet-mask'],
                       'type': self.original_if['type']}
            self.csr.put_request('interfaces/GigabitEthernet1',
                                 payload=payload)
            if self.csr.status != requests.codes.NO_CONTENT:
                self.fail("Unable to restore I/F Ge1 description after test")

    def setUp(self, host='localhost', tunnel_ip='10.10.10.10', timeout=None):
        """Prepare for PUT API tests."""
        super(TestCsrPutRestApi, self).setUp()
        info = {'rest_mgmt_ip': host, 'tunnel_ip': tunnel_ip,
                'username': 'stack', 'password': 'cisco', 'timeout': timeout}
        self.csr = csr_client.CsrRestClient(info)

        self._save_resources()
        self.addCleanup(self._restore_resources, 'stack', 'cisco')

    def test_put_requests(self):
        """Simple PUT requests (repeatable).

        First request will do a post to get token (login). Assumes
        that there are two interfaces on the CSR (Ge1 and Ge2).
        """

        with httmock.HTTMock(csr_request.token,
                             csr_request.put,
                             csr_request.normal_get):
            payload = {'host-name': 'TestHost'}
            content = self.csr.put_request('global/host-name',
                                           payload=payload)
            self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)
            self.assertIsNone(content)

            payload = {'host-name': 'TestHost2'}
            content = self.csr.put_request('global/host-name',
                                           payload=payload)
            self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)
            self.assertIsNone(content)

    def test_change_interface_description(self):
        """Test that interface description can be changed.

        This was a problem with an earlier version of the CSR image and is
        here to prevent regression.
        """
        with httmock.HTTMock(csr_request.token,
                             csr_request.put,
                             csr_request.normal_get):
            payload = {'description': u'Changed description',
                       'if-name': self.original_if['if-name'],
                       'ip-address': self.original_if['ip-address'],
                       'subnet-mask': self.original_if['subnet-mask'],
                       'type': self.original_if['type']}
            content = self.csr.put_request(
                'interfaces/GigabitEthernet1', payload=payload)
            self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)
            self.assertIsNone(content)
            content = self.csr.get_request('interfaces/GigabitEthernet1')
            self.assertEqual(requests.codes.OK, self.csr.status)
            self.assertIn('description', content)
            self.assertEqual(u'Changed description',
                             content['description'])

    def ignore_test_change_to_empty_interface_description(self):
        """Test that interface description can be changed to empty string.

        This is a problem in the current version of the CSR image, which
        rejects the change with a 400 error. This test is here to prevent
        a regression (once it is fixed) Note that there is code in the
        test setup to change the description to a non-empty string to
        avoid failures in other tests.
        """
        with httmock.HTTMock(csr_request.token,
                             csr_request.put,
                             csr_request.normal_get):
            payload = {'description': '',
                       'if-name': self.original_if['if-name'],
                       'ip-address': self.original_if['ip-address'],
                       'subnet-mask': self.original_if['subnet-mask'],
                       'type': self.original_if['type']}
            content = self.csr.put_request(
                'interfaces/GigabitEthernet1', payload=payload)
            self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)
            self.assertIsNone(content)
            content = self.csr.get_request('interfaces/GigabitEthernet1')
            self.assertEqual(requests.codes.OK, self.csr.status)
            self.assertIn('description', content)
            self.assertEqual('', content['description'])


class TestCsrDeleteRestApi(base.BaseTestCase):

    """Test CSR DELETE REST API."""

    def setUp(self, host='localhost', tunnel_ip='10.10.10.10', timeout=None):
        super(TestCsrDeleteRestApi, self).setUp()
        info = {'rest_mgmt_ip': host, 'tunnel_ip': tunnel_ip,
                'username': 'stack', 'password': 'cisco', 'timeout': timeout}
        self.csr = csr_client.CsrRestClient(info)

    def _make_dummy_user(self):
        """Create a user that will be later deleted."""
        self.csr.post_request('global/local-users',
                              payload={'username': 'dummy',
                                       'password': 'dummy',
                                       'privilege': 15})
        self.assertEqual(requests.codes.CREATED, self.csr.status)

    def test_delete_requests(self):
        """Simple DELETE requests (creating entry first)."""
        with httmock.HTTMock(csr_request.token,
                             csr_request.post,
                             csr_request.delete):
            self._make_dummy_user()
            self.csr.token = None  # Force login
            self.csr.delete_request('global/local-users/dummy')
            self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)
            # Delete again, but without logging in this time
            self._make_dummy_user()
            self.csr.delete_request('global/local-users/dummy')
            self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)

    def test_delete_non_existent_entry(self):
        """Negative test of trying to delete a non-existent user."""
        with httmock.HTTMock(csr_request.token,
                             csr_request.delete_unknown):
            content = self.csr.delete_request('global/local-users/unknown')
            self.assertEqual(requests.codes.NOT_FOUND, self.csr.status)
            expected = {u'error-code': -1,
                        u'error-message': u'user unknown not found'}
            self.assertDictContainsSubset(expected, content)

    def test_delete_not_allowed(self):
        """Negative test of trying to delete the host-name."""
        with httmock.HTTMock(csr_request.token,
                             csr_request.delete_not_allowed):
            self.csr.delete_request('global/host-name')
            self.assertEqual(requests.codes.METHOD_NOT_ALLOWED,
                             self.csr.status)


class TestCsrRestApiFailures(base.BaseTestCase):

    """Test failure cases common for all REST APIs.

    Uses the lower level _do_request() to just perform the operation and get
    the result, without any error handling.
    """

    def setUp(self, host='localhost', tunnel_ip='10.10.10.10', timeout=0.1):
        super(TestCsrRestApiFailures, self).setUp()
        info = {'rest_mgmt_ip': host, 'tunnel_ip': tunnel_ip,
                'username': 'stack', 'password': 'cisco', 'timeout': timeout}
        self.csr = csr_client.CsrRestClient(info)

    def test_request_for_non_existent_resource(self):
        """Negative test of non-existent resource on REST request."""
        with httmock.HTTMock(csr_request.token,
                             csr_request.no_such_resource):
            self.csr.post_request('no/such/request')
            self.assertEqual(requests.codes.NOT_FOUND, self.csr.status)
            # The result is HTTP 404 message, so no error content to check

    def test_timeout_during_request(self):
        """Negative test of timeout during REST request."""
        with httmock.HTTMock(csr_request.token,
                             csr_request.timeout):
            self.csr._do_request('GET', 'global/host-name')
            self.assertEqual(requests.codes.REQUEST_TIMEOUT, self.csr.status)

    def test_token_expired_on_request(self):
        """Token expired before trying a REST request.

        The mock is configured to return a 401 error on the first
        attempt to reference the host name. Simulate expiration of
        token by changing it.
        """

        with httmock.HTTMock(csr_request.token,
                             csr_request.expired_request,
                             csr_request.normal_get):
            self.csr.token = '123'  # These are 44 characters, so won't match
            content = self.csr._do_request('GET', 'global/host-name')
            self.assertEqual(requests.codes.OK, self.csr.status)
            self.assertIn('host-name', content)
            self.assertNotEqual(None, content['host-name'])

    def test_failed_to_obtain_token_for_request(self):
        """Negative test of unauthorized user for REST request."""
        self.csr.auth = ('stack', 'bogus')
        with httmock.HTTMock(csr_request.token_unauthorized):
            self.csr._do_request('GET', 'global/host-name')
            self.assertEqual(requests.codes.UNAUTHORIZED, self.csr.status)


class TestCsrRestIkePolicyCreate(base.BaseTestCase):

    """Test IKE policy create REST requests."""

    def setUp(self, host='localhost', tunnel_ip='10.10.10.10', timeout=None):
        super(TestCsrRestIkePolicyCreate, self).setUp()
        info = {'rest_mgmt_ip': host, 'tunnel_ip': tunnel_ip,
                'username': 'stack', 'password': 'cisco', 'timeout': timeout}
        self.csr = csr_client.CsrRestClient(info)

    def test_create_delete_ike_policy(self):
        """Create and then delete IKE policy."""
        with httmock.HTTMock(csr_request.token,
                             csr_request.post,
                             csr_request.normal_get):
            policy_id = '2'
            policy_info = {u'priority-id': u'%s' % policy_id,
                           u'encryption': u'aes256',
                           u'hash': u'sha',
                           u'dhGroup': 5,
                           u'lifetime': 3600}
            location = self.csr.create_ike_policy(policy_info)
            self.assertEqual(requests.codes.CREATED, self.csr.status)
            self.assertIn('vpn-svc/ike/policies/%s' % policy_id, location)
            # Check the hard-coded items that get set as well...
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(requests.codes.OK, self.csr.status)
            expected_policy = {u'kind': u'object#ike-policy',
                               u'version': u'v1',
                               u'local-auth-method': u'pre-share'}
            expected_policy.update(policy_info)
            self.assertEqual(expected_policy, content)
        # Now delete and verify the IKE policy is gone
        with httmock.HTTMock(csr_request.token,
                             csr_request.delete,
                             csr_request.no_such_resource):
            self.csr.delete_ike_policy(policy_id)
            self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(requests.codes.NOT_FOUND, self.csr.status)

    def test_create_ike_policy_with_defaults(self):
        """Create IKE policy using defaults for all optional values."""
        with httmock.HTTMock(csr_request.token,
                             csr_request.post,
                             csr_request.get_defaults):
            policy_id = '2'
            policy_info = {u'priority-id': u'%s' % policy_id}
            location = self.csr.create_ike_policy(policy_info)
            self.assertEqual(requests.codes.CREATED, self.csr.status)
            self.assertIn('vpn-svc/ike/policies/%s' % policy_id, location)
            # Check the hard-coded items that get set as well...
            content = self.csr.get_request(location, full_url=True)
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
            self.assertEqual(expected_policy, content)

    def test_create_duplicate_ike_policy(self):
        """Negative test of trying to create a duplicate IKE policy."""
        with httmock.HTTMock(csr_request.token,
                             csr_request.post,
                             csr_request.normal_get):
            policy_id = '2'
            policy_info = {u'priority-id': u'%s' % policy_id,
                           u'encryption': u'aes',
                           u'hash': u'sha',
                           u'dhGroup': 5,
                           u'lifetime': 3600}
            location = self.csr.create_ike_policy(policy_info)
            self.assertEqual(requests.codes.CREATED, self.csr.status)
            self.assertIn('vpn-svc/ike/policies/%s' % policy_id, location)
        with httmock.HTTMock(csr_request.token,
                             csr_request.post_duplicate):
            location = self.csr.create_ike_policy(policy_info)
            self.assertEqual(requests.codes.BAD_REQUEST, self.csr.status)
            expected = {u'error-code': -1,
                        u'error-message': u'policy 2 exist, not allow to '
                        u'update policy using POST method'}
            self.assertDictContainsSubset(expected, location)


class TestCsrRestIPSecPolicyCreate(base.BaseTestCase):

    """Test IPSec policy create REST requests."""

    def setUp(self, host='localhost', tunnel_ip='10.10.10.10', timeout=None):
        super(TestCsrRestIPSecPolicyCreate, self).setUp()
        info = {'rest_mgmt_ip': host, 'tunnel_ip': tunnel_ip,
                'username': 'stack', 'password': 'cisco', 'timeout': timeout}
        self.csr = csr_client.CsrRestClient(info)

    def test_create_delete_ipsec_policy(self):
        """Create and then delete IPSec policy."""
        with httmock.HTTMock(csr_request.token,
                             csr_request.post,
                             csr_request.normal_get):
            policy_id = '123'
            policy_info = {
                u'policy-id': u'%s' % policy_id,
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
            self.assertIn('vpn-svc/ipsec/policies/%s' % policy_id, location)
            # Check the hard-coded items that get set as well...
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(requests.codes.OK, self.csr.status)
            expected_policy = {u'kind': u'object#ipsec-policy',
                               u'mode': u'tunnel',
                               u'lifetime-kb': 4608000,
                               u'idle-time': None}
            expected_policy.update(policy_info)
            # CSR will respond with capitalized value
            expected_policy[u'anti-replay-window-size'] = u'Disable'
            self.assertEqual(expected_policy, content)
        # Now delete and verify the IPSec policy is gone
        with httmock.HTTMock(csr_request.token,
                             csr_request.delete,
                             csr_request.no_such_resource):
            self.csr.delete_ipsec_policy(policy_id)
            self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(requests.codes.NOT_FOUND, self.csr.status)

    def test_create_ipsec_policy_with_defaults(self):
        """Create IPSec policy with default for all optional values."""
        with httmock.HTTMock(csr_request.token,
                             csr_request.post,
                             csr_request.get_defaults):
            policy_id = '123'
            policy_info = {
                u'policy-id': u'%s' % policy_id,
            }
            location = self.csr.create_ipsec_policy(policy_info)
            self.assertEqual(requests.codes.CREATED, self.csr.status)
            self.assertIn('vpn-svc/ipsec/policies/%s' % policy_id, location)
            # Check the hard-coded items that get set as well...
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(requests.codes.OK, self.csr.status)
            expected_policy = {u'kind': u'object#ipsec-policy',
                               u'mode': u'tunnel',
                               u'protection-suite': {},
                               u'lifetime-sec': 3600,
                               u'pfs': u'Disable',
                               u'anti-replay-window-size': u'None',
                               u'lifetime-kb': 4608000,
                               u'idle-time': None}
            expected_policy.update(policy_info)
            self.assertEqual(expected_policy, content)

    def test_create_ipsec_policy_with_uuid(self):
        """Create IPSec policy using UUID for id."""
        with httmock.HTTMock(csr_request.token,
                             csr_request.post,
                             csr_request.normal_get):
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
            self.assertIn('vpn-svc/ipsec/policies/%s' % dummy_policy_id,
                          location)
            # Check the hard-coded items that get set as well...
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(requests.codes.OK, self.csr.status)
            expected_policy = {u'kind': u'object#ipsec-policy',
                               u'mode': u'tunnel',
                               u'lifetime-kb': 4608000,
                               u'idle-time': None}
            expected_policy.update(policy_info)
            # CSR will respond with capitalized value
            expected_policy[u'anti-replay-window-size'] = u'Disable'
            self.assertEqual(expected_policy, content)

    def test_create_ipsec_policy_without_ah(self):
        """Create IPSec policy."""
        with httmock.HTTMock(csr_request.token,
                             csr_request.post,
                             csr_request.get_no_ah):
            policy_id = '10'
            policy_info = {
                u'policy-id': u'%s' % policy_id,
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
            self.assertIn('vpn-svc/ipsec/policies/%s' % policy_id, location)
            # Check the hard-coded items that get set as well...
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(requests.codes.OK, self.csr.status)
            expected_policy = {u'kind': u'object#ipsec-policy',
                               u'mode': u'tunnel',
                               u'lifetime-kb': 4608000,
                               u'idle-time': None}
            expected_policy.update(policy_info)
            self.assertEqual(expected_policy, content)

    def test_invalid_ipsec_policy_lifetime(self):
        """Failure test of IPSec policy with unsupported lifetime."""
        with httmock.HTTMock(csr_request.token,
                             csr_request.post_bad_lifetime):
            policy_id = '123'
            policy_info = {
                u'policy-id': u'%s' % policy_id,
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
        with httmock.HTTMock(csr_request.token,
                             csr_request.post_bad_name,
                             csr_request.get_defaults):
            policy_id = 'policy-name-is-too-long-32-chars'
            policy_info = {
                u'policy-id': u'%s' % policy_id,
            }
            self.csr.create_ipsec_policy(policy_info)
            self.assertEqual(requests.codes.BAD_REQUEST, self.csr.status)


class TestCsrRestPreSharedKeyCreate(base.BaseTestCase):

    """Test Pre-shared key (PSK) create REST requests."""

    def setUp(self, host='localhost', tunnel_ip='10.10.10.10', timeout=None):
        super(TestCsrRestPreSharedKeyCreate, self).setUp()
        info = {'rest_mgmt_ip': host, 'tunnel_ip': tunnel_ip,
                'username': 'stack', 'password': 'cisco', 'timeout': timeout}
        self.csr = csr_client.CsrRestClient(info)

    def test_create_delete_pre_shared_key(self):
        """Create and then delete a keyring entry for pre-shared key."""
        with httmock.HTTMock(csr_request.token,
                             csr_request.post,
                             csr_request.normal_get):
            psk_id = '5'
            psk_info = {u'keyring-name': u'%s' % psk_id,
                        u'pre-shared-key-list': [
                            {u'key': u'super-secret',
                             u'encrypted': False,
                             u'peer-address': u'10.10.10.20/24'}
                        ]}
            location = self.csr.create_pre_shared_key(psk_info)
            self.assertEqual(requests.codes.CREATED, self.csr.status)
            self.assertIn('vpn-svc/ike/keyrings/%s' % psk_id, location)
            # Check the hard-coded items that get set as well...
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(requests.codes.OK, self.csr.status)
            expected_policy = {u'kind': u'object#ike-keyring'}
            expected_policy.update(psk_info)
            # Note: the peer CIDR is returned as an IP and mask
            expected_policy[u'pre-shared-key-list'][0][u'peer-address'] = (
                u'10.10.10.20 255.255.255.0')
            self.assertEqual(expected_policy, content)
        # Now delete and verify pre-shared key is gone
        with httmock.HTTMock(csr_request.token,
                             csr_request.delete,
                             csr_request.no_such_resource):
            self.csr.delete_pre_shared_key(psk_id)
            self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(requests.codes.NOT_FOUND, self.csr.status)

    def test_create_pre_shared_key_with_fqdn_peer(self):
        """Create pre-shared key using FQDN for peer address."""
        with httmock.HTTMock(csr_request.token,
                             csr_request.post,
                             csr_request.get_fqdn):
            psk_id = '5'
            psk_info = {u'keyring-name': u'%s' % psk_id,
                        u'pre-shared-key-list': [
                            {u'key': u'super-secret',
                             u'encrypted': False,
                             u'peer-address': u'cisco.com'}
                        ]}
            location = self.csr.create_pre_shared_key(psk_info)
            self.assertEqual(requests.codes.CREATED, self.csr.status)
            self.assertIn('vpn-svc/ike/keyrings/%s' % psk_id, location)
            # Check the hard-coded items that get set as well...
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(requests.codes.OK, self.csr.status)
            expected_policy = {u'kind': u'object#ike-keyring'}
            expected_policy.update(psk_info)
            self.assertEqual(expected_policy, content)

    def test_create_pre_shared_key_with_duplicate_peer_address(self):
        """Negative test of creating a second pre-shared key with same peer."""
        with httmock.HTTMock(csr_request.token,
                             csr_request.post,
                             csr_request.normal_get):
            psk_id = '5'
            psk_info = {u'keyring-name': u'%s' % psk_id,
                        u'pre-shared-key-list': [
                            {u'key': u'super-secret',
                             u'encrypted': False,
                             u'peer-address': u'10.10.10.20/24'}
                        ]}
            location = self.csr.create_pre_shared_key(psk_info)
            self.assertEqual(requests.codes.CREATED, self.csr.status)
            self.assertIn('vpn-svc/ike/keyrings/%s' % psk_id, location)
        with httmock.HTTMock(csr_request.token,
                             csr_request.post_duplicate):
            psk_id = u'6'
            another_psk_info = {u'keyring-name': psk_id,
                                u'pre-shared-key-list': [
                                    {u'key': u'abc123def',
                                     u'encrypted': False,
                                     u'peer-address': u'10.10.10.20/24'}
                                ]}
            self.csr.create_ike_policy(another_psk_info)
            self.assertEqual(requests.codes.BAD_REQUEST, self.csr.status)


class TestCsrRestIPSecConnectionCreate(base.BaseTestCase):

    """Test IPSec site-to-site connection REST requests.

    This requires us to have first created an IKE policy, IPSec policy,
    and pre-shared key, so it's more of an itegration test, when used
    with a real CSR (as we can't mock out these pre-conditions.
    """

    def setUp(self, host='localhost', tunnel_ip='10.10.10.10', timeout=None):
        super(TestCsrRestIPSecConnectionCreate, self).setUp()
        info = {'rest_mgmt_ip': host, 'tunnel_ip': tunnel_ip,
                'username': 'stack', 'password': 'cisco', 'timeout': timeout}
        self.csr = csr_client.CsrRestClient(info)

    def _make_psk_for_test(self):
        psk_id = generate_pre_shared_key_id()
        self._remove_resource_for_test(self.csr.delete_pre_shared_key,
                                       psk_id)
        with httmock.HTTMock(csr_request.token,
                             csr_request.post):
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
        with httmock.HTTMock(csr_request.token,
                             csr_request.post):
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
        with httmock.HTTMock(csr_request.token,
                             csr_request.post):
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
        with httmock.HTTMock(csr_request.token,
                             csr_request.delete):
            delete_resource(resource_id)

    def _prepare_for_site_conn_create(self, skip_psk=False, skip_ike=False,
                                      skip_ipsec=False):
        """Create the policies and PSK so can then create site conn."""
        if not skip_psk:
            self._make_psk_for_test()
        if not skip_ike:
            self._make_ike_policy_for_test()
        if not skip_ipsec:
            ipsec_policy_id = self._make_ipsec_policy_for_test()
        else:
            ipsec_policy_id = generate_ipsec_policy_id()
        # Note: Use same ID number for tunnel and IPSec policy, so that when
        # GET tunnel info, the mocks can infer the IPSec policy ID from the
        # tunnel number.
        return (ipsec_policy_id, ipsec_policy_id)

    def test_create_delete_ipsec_connection(self):
        """Create and then delete an IPSec connection."""
        tunnel_id, ipsec_policy_id = self._prepare_for_site_conn_create()
        with httmock.HTTMock(csr_request.token,
                             csr_request.post,
                             csr_request.normal_get):
            connection_info = {
                u'vpn-interface-name': u'Tunnel%d' % tunnel_id,
                u'ipsec-policy-id': u'%d' % ipsec_policy_id,
                u'mtu': 1500,
                u'local-device': {u'ip-address': u'10.3.0.1/24',
                                  u'tunnel-ip-address': u'10.10.10.10'},
                u'remote-device': {u'tunnel-ip-address': u'10.10.10.20'}
            }
            location = self.csr.create_ipsec_connection(connection_info)
            self.addCleanup(self._remove_resource_for_test,
                            self.csr.delete_ipsec_connection,
                            'Tunnel%d' % tunnel_id)
            self.assertEqual(requests.codes.CREATED, self.csr.status)
            self.assertIn('vpn-svc/site-to-site/Tunnel%d' % tunnel_id,
                          location)
            # Check the hard-coded items that get set as well...
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(requests.codes.OK, self.csr.status)
            expected_connection = {u'kind': u'object#vpn-site-to-site',
                                   u'ike-profile-id': None,
                                   u'mtu': 1500,
                                   u'ip-version': u'ipv4'}
            expected_connection.update(connection_info)
            self.assertEqual(expected_connection, content)
        # Now delete and verify that site-to-site connection is gone
        with httmock.HTTMock(csr_request.token,
                             csr_request.delete,
                             csr_request.no_such_resource):
            # Only delete connection. Cleanup will take care of prerequisites
            self.csr.delete_ipsec_connection('Tunnel%d' % tunnel_id)
            self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(requests.codes.NOT_FOUND, self.csr.status)

    def test_create_ipsec_connection_with_no_tunnel_subnet(self):
        """Create an IPSec connection without an IP address on tunnel."""
        tunnel_id, ipsec_policy_id = self._prepare_for_site_conn_create()
        with httmock.HTTMock(csr_request.token,
                             csr_request.post,
                             csr_request.get_unnumbered):
            connection_info = {
                u'vpn-interface-name': u'Tunnel%d' % tunnel_id,
                u'ipsec-policy-id': u'%d' % ipsec_policy_id,
                u'local-device': {u'ip-address': u'GigabitEthernet3',
                                  u'tunnel-ip-address': u'10.10.10.10'},
                u'remote-device': {u'tunnel-ip-address': u'10.10.10.20'}
            }
            location = self.csr.create_ipsec_connection(connection_info)
            self.addCleanup(self._remove_resource_for_test,
                            self.csr.delete_ipsec_connection,
                            'Tunnel%d' % tunnel_id)
            self.assertEqual(requests.codes.CREATED, self.csr.status)
            self.assertIn('vpn-svc/site-to-site/Tunnel%d' % tunnel_id,
                          location)
            # Check the hard-coded items that get set as well...
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(requests.codes.OK, self.csr.status)
            expected_connection = {u'kind': u'object#vpn-site-to-site',
                                   u'ike-profile-id': None,
                                   u'mtu': 1500,
                                   u'ip-version': u'ipv4'}
            expected_connection.update(connection_info)
            self.assertEqual(expected_connection, content)

    def test_create_ipsec_connection_no_pre_shared_key(self):
        """Test of connection create without associated pre-shared key.

        The CSR will create the connection, but will not be able to pass
        traffic without the pre-shared key.
        """

        tunnel_id, ipsec_policy_id = self._prepare_for_site_conn_create(
            skip_psk=True)
        with httmock.HTTMock(csr_request.token,
                             csr_request.post,
                             csr_request.normal_get):
            connection_info = {
                u'vpn-interface-name': u'Tunnel%d' % tunnel_id,
                u'ipsec-policy-id': u'%d' % ipsec_policy_id,
                u'mtu': 1500,
                u'local-device': {u'ip-address': u'10.3.0.1/24',
                                  u'tunnel-ip-address': u'10.10.10.10'},
                u'remote-device': {u'tunnel-ip-address': u'10.10.10.20'}
            }
            location = self.csr.create_ipsec_connection(connection_info)
            self.addCleanup(self._remove_resource_for_test,
                            self.csr.delete_ipsec_connection,
                            'Tunnel%d' % tunnel_id)
            self.assertEqual(requests.codes.CREATED, self.csr.status)
            self.assertIn('vpn-svc/site-to-site/Tunnel%d' % tunnel_id,
                          location)
            # Check the hard-coded items that get set as well...
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(requests.codes.OK, self.csr.status)
            expected_connection = {u'kind': u'object#vpn-site-to-site',
                                   u'ike-profile-id': None,
                                   u'mtu': 1500,
                                   u'ip-version': u'ipv4'}
            expected_connection.update(connection_info)
            self.assertEqual(expected_connection, content)

    def test_create_ipsec_connection_with_default_ike_policy(self):
        """Test of connection create without IKE policy (uses default).

        Without an IKE policy, the CSR will use a built-in default IKE
        policy setting for the connection.
        """

        tunnel_id, ipsec_policy_id = self._prepare_for_site_conn_create(
            skip_ike=True)
        with httmock.HTTMock(csr_request.token,
                             csr_request.post,
                             csr_request.normal_get):
            connection_info = {
                u'vpn-interface-name': u'Tunnel%d' % tunnel_id,
                u'ipsec-policy-id': u'%d' % ipsec_policy_id,
                u'mtu': 1500,
                u'local-device': {u'ip-address': u'10.3.0.1/24',
                                  u'tunnel-ip-address': u'10.10.10.10'},
                u'remote-device': {u'tunnel-ip-address': u'10.10.10.20'}
            }
            location = self.csr.create_ipsec_connection(connection_info)
            self.addCleanup(self._remove_resource_for_test,
                            self.csr.delete_ipsec_connection,
                            'Tunnel%d' % tunnel_id)
            self.assertEqual(requests.codes.CREATED, self.csr.status)
            self.assertIn('vpn-svc/site-to-site/Tunnel%d' % tunnel_id,
                          location)
            # Check the hard-coded items that get set as well...
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(requests.codes.OK, self.csr.status)
            expected_connection = {u'kind': u'object#vpn-site-to-site',
                                   u'ike-profile-id': None,
                                   u'mtu': 1500,
                                   u'ip-version': u'ipv4'}
            expected_connection.update(connection_info)
            self.assertEqual(expected_connection, content)

    def test_set_ipsec_connection_admin_state_changes(self):
        """Create IPSec connection in admin down state."""
        tunnel_id, ipsec_policy_id = self._prepare_for_site_conn_create()
        tunnel = u'Tunnel%d' % tunnel_id
        with httmock.HTTMock(csr_request.token,
                             csr_request.post):
            connection_info = {
                u'vpn-interface-name': tunnel,
                u'ipsec-policy-id': u'%d' % ipsec_policy_id,
                u'mtu': 1500,
                u'local-device': {u'ip-address': u'10.3.0.1/24',
                                  u'tunnel-ip-address': u'10.10.10.10'},
                u'remote-device': {u'tunnel-ip-address': u'10.10.10.20'}
            }
            location = self.csr.create_ipsec_connection(connection_info)
            self.addCleanup(self._remove_resource_for_test,
                            self.csr.delete_ipsec_connection,
                            tunnel)
            self.assertEqual(requests.codes.CREATED, self.csr.status)
            self.assertIn('vpn-svc/site-to-site/%s' % tunnel, location)
        state_uri = location + "/state"
        # Note: When created, the tunnel will be in admin 'up' state
        # Note: Line protocol state will be down, unless have an active conn.
        expected_state = {u'kind': u'object#vpn-site-to-site-state',
                          u'vpn-interface-name': tunnel,
                          u'line-protocol-state': u'down',
                          u'enabled': False}
        with httmock.HTTMock(csr_request.put,
                             csr_request.get_admin_down):
            self.csr.set_ipsec_connection_state(tunnel, admin_up=False)
            self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)
            content = self.csr.get_request(state_uri, full_url=True)
            self.assertEqual(requests.codes.OK, self.csr.status)
            self.assertEqual(expected_state, content)

        with httmock.HTTMock(csr_request.put,
                             csr_request.get_admin_up):
            self.csr.set_ipsec_connection_state(tunnel, admin_up=True)
            self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)
            content = self.csr.get_request(state_uri, full_url=True)
            self.assertEqual(requests.codes.OK, self.csr.status)
            expected_state[u'enabled'] = True
            self.assertEqual(expected_state, content)

    def test_create_ipsec_connection_missing_ipsec_policy(self):
        """Negative test of connection create without IPSec policy."""
        tunnel_id, ipsec_policy_id = self._prepare_for_site_conn_create(
            skip_ipsec=True)
        with httmock.HTTMock(
                csr_request.token,
                csr_request.post_missing_ipsec_policy):
            connection_info = {
                u'vpn-interface-name': u'Tunnel%d' % tunnel_id,
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
        with httmock.HTTMock(csr_request.token,
                             csr_request.get_local_ip):
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
        tunnel_id, ipsec_policy_id = self._prepare_for_site_conn_create()
        with httmock.HTTMock(csr_request.token,
                             csr_request.post_bad_ip):
            connection_info = {
                u'vpn-interface-name': u'Tunnel%d' % tunnel_id,
                u'ipsec-policy-id': u'%d' % ipsec_policy_id,
                u'local-device': {u'ip-address': u'%s/24' % conflicting_ip,
                                  u'tunnel-ip-address': u'10.10.10.10'},
                u'remote-device': {u'tunnel-ip-address': u'10.10.10.20'}
            }
            self.csr.create_ipsec_connection(connection_info)
            self.addCleanup(self._remove_resource_for_test,
                            self.csr.delete_ipsec_connection,
                            'Tunnel%d' % tunnel_id)
            self.assertEqual(requests.codes.BAD_REQUEST, self.csr.status)

    def test_create_ipsec_connection_with_max_mtu(self):
        """Create an IPSec connection with max MTU value."""
        tunnel_id, ipsec_policy_id = self._prepare_for_site_conn_create()
        with httmock.HTTMock(csr_request.token,
                             csr_request.post,
                             csr_request.get_mtu):
            connection_info = {
                u'vpn-interface-name': u'Tunnel%d' % tunnel_id,
                u'ipsec-policy-id': u'%d' % ipsec_policy_id,
                u'mtu': 9192,
                u'local-device': {u'ip-address': u'10.3.0.1/24',
                                  u'tunnel-ip-address': u'10.10.10.10'},
                u'remote-device': {u'tunnel-ip-address': u'10.10.10.20'}
            }
            location = self.csr.create_ipsec_connection(connection_info)
            self.addCleanup(self._remove_resource_for_test,
                            self.csr.delete_ipsec_connection,
                            'Tunnel%d' % tunnel_id)
            self.assertEqual(requests.codes.CREATED, self.csr.status)
            self.assertIn('vpn-svc/site-to-site/Tunnel%d' % tunnel_id,
                          location)
            # Check the hard-coded items that get set as well...
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(requests.codes.OK, self.csr.status)
            expected_connection = {u'kind': u'object#vpn-site-to-site',
                                   u'ike-profile-id': None,
                                   u'ip-version': u'ipv4'}
            expected_connection.update(connection_info)
            self.assertEqual(expected_connection, content)

    def test_create_ipsec_connection_with_bad_mtu(self):
        """Negative test of connection create with unsupported MTU value."""
        tunnel_id, ipsec_policy_id = self._prepare_for_site_conn_create()
        with httmock.HTTMock(csr_request.token,
                             csr_request.post_bad_mtu):
            connection_info = {
                u'vpn-interface-name': u'Tunnel%d' % tunnel_id,
                u'ipsec-policy-id': u'%d' % ipsec_policy_id,
                u'mtu': 9193,
                u'local-device': {u'ip-address': u'10.3.0.1/24',
                                  u'tunnel-ip-address': u'10.10.10.10'},
                u'remote-device': {u'tunnel-ip-address': u'10.10.10.20'}
            }
            self.csr.create_ipsec_connection(connection_info)
            self.addCleanup(self._remove_resource_for_test,
                            self.csr.delete_ipsec_connection,
                            'Tunnel%d' % tunnel_id)
            self.assertEqual(requests.codes.BAD_REQUEST, self.csr.status)

    def test_status_when_no_tunnels_exist(self):
        """Get status, when there are no tunnels."""
        with httmock.HTTMock(csr_request.token,
                             csr_request.get_none):
            tunnels = self.csr.read_tunnel_statuses()
            self.assertEqual(requests.codes.OK, self.csr.status)
            self.assertEqual([], tunnels)

    def test_status_for_one_tunnel(self):
        """Get status of one tunnel."""
        # Create the IPsec site-to-site connection first
        tunnel_id, ipsec_policy_id = self._prepare_for_site_conn_create()
        tunnel_id = 123  # Must hard code to work with mock
        with httmock.HTTMock(csr_request.token,
                             csr_request.post,
                             csr_request.normal_get):
            connection_info = {
                u'vpn-interface-name': u'Tunnel123',
                u'ipsec-policy-id': u'%d' % ipsec_policy_id,
                u'local-device': {u'ip-address': u'10.3.0.1/24',
                                  u'tunnel-ip-address': u'10.10.10.10'},
                u'remote-device': {u'tunnel-ip-address': u'10.10.10.20'}
            }
            location = self.csr.create_ipsec_connection(connection_info)
            self.addCleanup(self._remove_resource_for_test,
                            self.csr.delete_ipsec_connection,
                            u'Tunnel123')
            self.assertEqual(requests.codes.CREATED, self.csr.status)
            self.assertIn('vpn-svc/site-to-site/Tunnel%d' % tunnel_id,
                          location)
        with httmock.HTTMock(csr_request.token,
                             csr_request.normal_get):
            tunnels = self.csr.read_tunnel_statuses()
            self.assertEqual(requests.codes.OK, self.csr.status)
            self.assertEqual([(u'Tunnel123', u'DOWN-NEGOTIATING'), ], tunnels)


class TestCsrRestIkeKeepaliveCreate(base.BaseTestCase):

    """Test IKE keepalive REST requests.

    Note: On the Cisco CSR, the IKE keepalive for v1 is a global configuration
    that applies to all VPN tunnels to specify Dead Peer Detection information.
    As a result, this REST API is not used in the OpenStack device driver, and
    the keepalive will default to zero (disabled).
    """

    def _save_dpd_info(self):
        with httmock.HTTMock(csr_request.token,
                             csr_request.normal_get):
            details = self.csr.get_request('vpn-svc/ike/keepalive')
            if self.csr.status == requests.codes.OK:
                self.dpd = details
                self.addCleanup(self._restore_dpd_info)
            elif self.csr.status != requests.codes.NOT_FOUND:
                self.fail("Unable to save original DPD info")

    def _restore_dpd_info(self):
        with httmock.HTTMock(csr_request.token,
                             csr_request.put):
            payload = {'interval': self.dpd['interval'],
                       'retry': self.dpd['retry']}
            self.csr.put_request('vpn-svc/ike/keepalive', payload=payload)
            if self.csr.status != requests.codes.NO_CONTENT:
                self.fail("Unable to restore DPD info after test")

    def setUp(self, host='localhost', tunnel_ip='10.10.10.10', timeout=None):
        super(TestCsrRestIkeKeepaliveCreate, self).setUp()
        info = {'rest_mgmt_ip': host, 'tunnel_ip': tunnel_ip,
                'username': 'stack', 'password': 'cisco', 'timeout': timeout}
        self.csr = csr_client.CsrRestClient(info)
        self._save_dpd_info()
        self.csr.token = None

    def test_configure_ike_keepalive(self):
        """Set IKE keep-alive (aka Dead Peer Detection) for the CSR."""
        with httmock.HTTMock(csr_request.token,
                             csr_request.put,
                             csr_request.normal_get):
            keepalive_info = {'interval': 60, 'retry': 4}
            self.csr.configure_ike_keepalive(keepalive_info)
            self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)
            content = self.csr.get_request('vpn-svc/ike/keepalive')
            self.assertEqual(requests.codes.OK, self.csr.status)
            expected = {'periodic': False}
            expected.update(keepalive_info)
            self.assertDictContainsSubset(expected, content)

    def test_disable_ike_keepalive(self):
        """Disable IKE keep-alive (aka Dead Peer Detection) for the CSR."""
        with httmock.HTTMock(csr_request.token,
                             csr_request.delete,
                             csr_request.put,
                             csr_request.get_not_configured):
            keepalive_info = {'interval': 0, 'retry': 4}
            self.csr.configure_ike_keepalive(keepalive_info)
            self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)


class TestCsrRestStaticRoute(base.BaseTestCase):

    """Test static route REST requests.

    A static route is added for the peer's private network. Would create
    a route for each of the peer CIDRs specified for the VPN connection.
    """

    def setUp(self, host='localhost', tunnel_ip='10.10.10.10', timeout=None):
        super(TestCsrRestStaticRoute, self).setUp()
        info = {'rest_mgmt_ip': host, 'tunnel_ip': tunnel_ip,
                'username': 'stack', 'password': 'cisco', 'timeout': timeout}
        self.csr = csr_client.CsrRestClient(info)

    def test_create_delete_static_route(self):
        """Create and then delete a static route for the tunnel."""
        cidr = u'10.1.0.0/24'
        interface = u'GigabitEthernet1'
        expected_id = '10.1.0.0_24_GigabitEthernet1'
        with httmock.HTTMock(csr_request.token,
                             csr_request.post,
                             csr_request.normal_get):
            route_info = {u'destination-network': cidr,
                          u'outgoing-interface': interface}
            location = self.csr.create_static_route(route_info)
            self.assertEqual(requests.codes.CREATED, self.csr.status)
            self.assertIn('routing-svc/static-routes/%s' % expected_id,
                          location)
            # Check the hard-coded items that get set as well...
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(requests.codes.OK, self.csr.status)
            expected_route = {u'kind': u'object#static-route',
                              u'next-hop-router': None,
                              u'admin-distance': 1}
            expected_route.update(route_info)
            self.assertEqual(expected_route, content)
        # Now delete and verify that static route is gone
        with httmock.HTTMock(csr_request.token,
                             csr_request.delete,
                             csr_request.no_such_resource):
            route_id = csr_client.make_route_id(cidr, interface)
            self.csr.delete_static_route(route_id)
            self.assertEqual(requests.codes.NO_CONTENT, self.csr.status)
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(requests.codes.NOT_FOUND, self.csr.status)
