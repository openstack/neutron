# Copyright (C) 2009-2012 VMware, Inc. All Rights Reserved.
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

import httplib
import new
import random

import eventlet
from eventlet.green import urllib2
import mock

from neutron.openstack.common.gettextutils import _LI
from neutron.openstack.common import log as logging
from neutron.plugins.vmware.api_client import eventlet_client as client
from neutron.plugins.vmware.api_client import eventlet_request as request
from neutron.tests import base
from neutron.tests.unit import vmware


LOG = logging.getLogger(__name__)


REQUEST_TIMEOUT = 1


def fetch(url):
    return urllib2.urlopen(url).read()


class ApiRequestEventletTest(base.BaseTestCase):

    def setUp(self):

        super(ApiRequestEventletTest, self).setUp()
        self.client = client.EventletApiClient(
            [("127.0.0.1", 4401, True)], "admin", "admin")
        self.url = "/ws.v1/_debug"
        self.req = request.EventletApiRequest(self.client, self.url)

    def tearDown(self):
        self.client = None
        self.req = None
        super(ApiRequestEventletTest, self).tearDown()

    def test_construct_eventlet_api_request(self):
        e = request.EventletApiRequest(self.client, self.url)
        self.assertIsNotNone(e)

    def test_apirequest_spawn(self):
        def x(id):
            eventlet.greenthread.sleep(random.random())
            LOG.info(_LI('spawned: %d'), id)

        for i in range(10):
            request.EventletApiRequest._spawn(x, i)

    def test_apirequest_start(self):
        for i in range(10):
            a = request.EventletApiRequest(
                self.client, self.url)
            a._handle_request = mock.Mock()
            a.start()
            eventlet.greenthread.sleep(0.1)
            LOG.info(_LI('_handle_request called: %s'),
                     a._handle_request.called)
        request.EventletApiRequest.joinall()

    def test_join_with_handle_request(self):
        self.req._handle_request = mock.Mock()
        self.req.start()
        self.req.join()
        self.assertTrue(self.req._handle_request.called)

    def test_join_without_handle_request(self):
        self.req._handle_request = mock.Mock()
        self.req.join()
        self.assertFalse(self.req._handle_request.called)

    def test_copy(self):
        req = self.req.copy()
        for att in [
                '_api_client', '_url', '_method', '_body', '_headers',
                '_http_timeout', '_request_timeout', '_retries',
                '_redirects', '_auto_login']:
            self.assertTrue(getattr(req, att) is getattr(self.req, att))

    def test_request_error(self):
        self.assertIsNone(self.req.request_error)

    def test_run_and_handle_request(self):
        self.req._request_timeout = None
        self.req._handle_request = mock.Mock()
        self.req.start()
        self.req.join()
        self.assertTrue(self.req._handle_request.called)

    def test_run_and_timeout(self):
        def my_handle_request(self):
            LOG.info('my_handle_request() self: %s' % self)
            LOG.info('my_handle_request() dir(self): %s' % dir(self))
            eventlet.greenthread.sleep(REQUEST_TIMEOUT * 2)

        self.req._request_timeout = REQUEST_TIMEOUT
        self.req._handle_request = new.instancemethod(
            my_handle_request, self.req, request.EventletApiRequest)
        self.req.start()
        self.assertIsNone(self.req.join())

    def prep_issue_request(self):
        mysock = mock.Mock()
        mysock.gettimeout.return_value = 4242

        myresponse = mock.Mock()
        myresponse.read.return_value = 'body'
        myresponse.getheaders.return_value = 'headers'
        myresponse.status = httplib.MOVED_PERMANENTLY

        myconn = mock.Mock()
        myconn.request.return_value = None
        myconn.sock = mysock
        myconn.getresponse.return_value = myresponse
        myconn.__str__ = mock.Mock()
        myconn.__str__.return_value = 'myconn string'

        req = self.req
        req._redirect_params = mock.Mock()
        req._redirect_params.return_value = (myconn, 'url')
        req._request_str = mock.Mock()
        req._request_str.return_value = 'http://cool/cool'

        client = self.client
        client.need_login = False
        client._auto_login = False
        client._auth_cookie = False
        client.acquire_connection = mock.Mock()
        client.acquire_connection.return_value = myconn
        client.release_connection = mock.Mock()

        return (mysock, myresponse, myconn)

    def test_issue_request_trigger_exception(self):
        (mysock, myresponse, myconn) = self.prep_issue_request()
        self.client.acquire_connection.return_value = None

        self.req._issue_request()
        self.assertIsInstance(self.req._request_error, Exception)
        self.assertTrue(self.client.acquire_connection.called)

    def test_issue_request_handle_none_sock(self):
        (mysock, myresponse, myconn) = self.prep_issue_request()
        myconn.sock = None
        self.req.start()
        self.assertIsNone(self.req.join())
        self.assertTrue(self.client.acquire_connection.called)

    def test_issue_request_exceed_maximum_retries(self):
        (mysock, myresponse, myconn) = self.prep_issue_request()
        self.req.start()
        self.assertIsNone(self.req.join())
        self.assertTrue(self.client.acquire_connection.called)

    def test_issue_request_trigger_non_redirect(self):
        (mysock, myresponse, myconn) = self.prep_issue_request()
        myresponse.status = httplib.OK
        self.req.start()
        self.assertIsNone(self.req.join())
        self.assertTrue(self.client.acquire_connection.called)

    def test_issue_request_trigger_internal_server_error(self):
        (mysock, myresponse, myconn) = self.prep_issue_request()
        self.req._redirect_params.return_value = (myconn, None)
        self.req.start()
        self.assertIsNone(self.req.join())
        self.assertTrue(self.client.acquire_connection.called)

    def test_redirect_params_break_on_location(self):
        myconn = mock.Mock()
        (conn, retval) = self.req._redirect_params(
            myconn, [('location', None)])
        self.assertIsNone(retval)

    def test_redirect_params_parse_a_url(self):
        myconn = mock.Mock()
        (conn, retval) = self.req._redirect_params(
            myconn, [('location', '/path/a/b/c')])
        self.assertIsNotNone(retval)

    def test_redirect_params_invalid_redirect_location(self):
        myconn = mock.Mock()
        (conn, retval) = self.req._redirect_params(
            myconn, [('location', '+path/a/b/c')])
        self.assertIsNone(retval)

    def test_redirect_params_invalid_scheme(self):
        myconn = mock.Mock()
        (conn, retval) = self.req._redirect_params(
            myconn, [('location', 'invalidscheme://hostname:1/path')])
        self.assertIsNone(retval)

    def test_redirect_params_setup_https_with_cooki(self):
        with mock.patch(vmware.CLIENT_NAME) as mock_client:
            api_client = mock_client.return_value
            self.req._api_client = api_client
            myconn = mock.Mock()
            (conn, retval) = self.req._redirect_params(
                myconn, [('location', 'https://host:1/path')])

            self.assertIsNotNone(retval)
            self.assertTrue(api_client.acquire_redirect_connection.called)

    def test_redirect_params_setup_htttps_and_query(self):
        with mock.patch(vmware.CLIENT_NAME) as mock_client:
            api_client = mock_client.return_value
            self.req._api_client = api_client
            myconn = mock.Mock()
            (conn, retval) = self.req._redirect_params(myconn, [
                ('location', 'https://host:1/path?q=1')])

            self.assertIsNotNone(retval)
            self.assertTrue(api_client.acquire_redirect_connection.called)

    def test_redirect_params_setup_https_connection_no_cookie(self):
        with mock.patch(vmware.CLIENT_NAME) as mock_client:
            api_client = mock_client.return_value
            self.req._api_client = api_client
            myconn = mock.Mock()
            (conn, retval) = self.req._redirect_params(myconn, [
                ('location', 'https://host:1/path')])

            self.assertIsNotNone(retval)
            self.assertTrue(api_client.acquire_redirect_connection.called)

    def test_redirect_params_setup_https_and_query_no_cookie(self):
        with mock.patch(vmware.CLIENT_NAME) as mock_client:
            api_client = mock_client.return_value
            self.req._api_client = api_client
            myconn = mock.Mock()
            (conn, retval) = self.req._redirect_params(
                myconn, [('location', 'https://host:1/path?q=1')])
            self.assertIsNotNone(retval)
            self.assertTrue(api_client.acquire_redirect_connection.called)

    def test_redirect_params_path_only_with_query(self):
        with mock.patch(vmware.CLIENT_NAME) as mock_client:
            api_client = mock_client.return_value
            api_client.wait_for_login.return_value = None
            api_client.auth_cookie = None
            api_client.acquire_connection.return_value = True
            myconn = mock.Mock()
            (conn, retval) = self.req._redirect_params(myconn, [
                ('location', '/path?q=1')])
            self.assertIsNotNone(retval)

    def test_handle_request_auto_login(self):
        self.req._auto_login = True
        self.req._api_client = mock.Mock()
        self.req._api_client.need_login = True
        self.req._request_str = mock.Mock()
        self.req._request_str.return_value = 'http://cool/cool'
        self.req.spawn = mock.Mock()
        self.req._handle_request()

    def test_handle_request_auto_login_unauth(self):
        self.req._auto_login = True
        self.req._api_client = mock.Mock()
        self.req._api_client.need_login = True
        self.req._request_str = mock.Mock()
        self.req._request_str.return_value = 'http://cool/cool'

        import socket
        resp = httplib.HTTPResponse(socket.socket())
        resp.status = httplib.UNAUTHORIZED
        mywaiter = mock.Mock()
        mywaiter.wait = mock.Mock()
        mywaiter.wait.return_value = resp
        self.req.spawn = mock.Mock(return_value=mywaiter)
        self.req._handle_request()

    def test_construct_eventlet_login_request(self):
        r = request.LoginRequestEventlet(self.client, 'user', 'password')
        self.assertIsNotNone(r)

    def test_session_cookie_session_cookie_retrieval(self):
        r = request.LoginRequestEventlet(self.client, 'user', 'password')
        r.successful = mock.Mock()
        r.successful.return_value = True
        r.value = mock.Mock()
        r.value.get_header = mock.Mock()
        r.value.get_header.return_value = 'cool'
        self.assertIsNotNone(r.session_cookie())

    def test_session_cookie_not_retrieved(self):
        r = request.LoginRequestEventlet(self.client, 'user', 'password')
        r.successful = mock.Mock()
        r.successful.return_value = False
        r.value = mock.Mock()
        r.value.get_header = mock.Mock()
        r.value.get_header.return_value = 'cool'
        self.assertIsNone(r.session_cookie())

    def test_construct_eventlet_get_api_providers_request(self):
        r = request.GetApiProvidersRequestEventlet(self.client)
        self.assertIsNotNone(r)

    def test_api_providers_none_api_providers(self):
        r = request.GetApiProvidersRequestEventlet(self.client)
        r.successful = mock.Mock(return_value=False)
        self.assertIsNone(r.api_providers())

    def test_api_providers_non_none_api_providers(self):
        r = request.GetApiProvidersRequestEventlet(self.client)
        r.value = mock.Mock()
        r.value.body = """{
          "results": [
            { "roles": [
              { "role": "api_provider",
                "listen_addr": "pssl:1.1.1.1:1" }]}]}"""
        r.successful = mock.Mock(return_value=True)
        LOG.info('%s' % r.api_providers())
        self.assertIsNotNone(r.api_providers())
