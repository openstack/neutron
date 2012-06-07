# Copyright (C) 2009-2012 Nicira Networks, Inc. All Rights Reserved.
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
import logging
import time
import urllib
import urlparse

import eventlet
from eventlet import timeout

from quantum.openstack.common import jsonutils
from quantum.plugins.nicira.nicira_nvp_plugin.api_client.common import (
    _conn_str,
    )
import quantum.plugins.nicira.nicira_nvp_plugin.api_client.request as request
import quantum.plugins.nicira.nicira_nvp_plugin.api_client.client_eventlet


logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger("nvp_api_request")


USER_AGENT = "NVP gevent client/1.0"

# Default parameters.
DEFAULT_REQUEST_TIMEOUT = 30
DEFAULT_HTTP_TIMEOUT = 10
DEFAULT_RETRIES = 2
DEFAULT_REDIRECTS = 2
API_REQUEST_POOL_SIZE = 10000


class NvpApiRequestEventlet:
    '''Eventlet-based ApiRequest class.

    This class will form the basis for eventlet-based ApiRequest classes
    (e.g. those used by the Quantum NVP Plugin).
    '''

    ALLOWED_STATUS_CODES = [
        httplib.OK,
        httplib.CREATED,
        httplib.NO_CONTENT,
        httplib.MOVED_PERMANENTLY,
        httplib.TEMPORARY_REDIRECT,
        httplib.BAD_REQUEST,
        httplib.UNAUTHORIZED,
        httplib.FORBIDDEN,
        httplib.NOT_FOUND,
        httplib.CONFLICT,
        httplib.INTERNAL_SERVER_ERROR,
        httplib.SERVICE_UNAVAILABLE,
    ]

    API_REQUEST_POOL = eventlet.GreenPool(API_REQUEST_POOL_SIZE)

    def __init__(self, nvp_api_client, url, method="GET", body=None,
                 headers=None,
                 request_timeout=DEFAULT_REQUEST_TIMEOUT,
                 retries=DEFAULT_RETRIES,
                 auto_login=True,
                 redirects=DEFAULT_REDIRECTS,
                 http_timeout=DEFAULT_HTTP_TIMEOUT):

        self._api_client = nvp_api_client
        self._url = url
        self._method = method
        self._body = body
        self._headers = headers or {}
        self._request_timeout = request_timeout
        self._retries = retries
        self._auto_login = auto_login
        self._redirects = redirects
        self._http_timeout = http_timeout

        self._request_error = None

        if "User-Agent" not in self._headers:
            self._headers["User-Agent"] = USER_AGENT

        self._green_thread = None

    @classmethod
    def _spawn(cls, func, *args, **kwargs):
        return cls.API_REQUEST_POOL.spawn(func, *args, **kwargs)

    def spawn(self, func, *args, **kwargs):
        return self.__class__._spawn(func, *args, **kwargs)

    @classmethod
    def joinall(cls):
        return cls.API_REQUEST_POOL.waitall()

    def join(self):
        if self._green_thread is not None:
            return self._green_thread.wait()
        LOG.error('Joining on invalid green thread')
        return Exception('Joining an invalid green thread')

    def start(self):
        self._green_thread = self.spawn(self._run)

    def copy(self):
        return NvpApiRequestEventlet(
            self._api_client, self._url, self._method, self._body,
            self._headers, self._request_timeout, self._retries,
            self._auto_login, self._redirects, self._http_timeout)

    @property
    def request_error(self):
        return self._request_error

    def _run(self):
        if self._request_timeout:
            # No timeout exception escapes the with block.
            with timeout.Timeout(self._request_timeout, False):
                return self._handle_request()

            LOG.info('Request timeout handling request.')
            self._request_error = Exception('Request timeout')
            return None
        else:
            return self._handle_request()

    def _request_str(self, conn, url):
        return "%s %s/%s" % (self._method, _conn_str(conn), url)

    def _issue_request(self):
        conn = self._api_client.acquire_connection()
        if conn is None:
            error = Exception("No API connections available")
            self._request_error = error
            return error

        url = self._url
        LOG.info("Issuing request '%s'" % self._request_str(conn, url))
        issued_time = time.time()
        is_conn_error = False
        try:
            redirects = 0
            while (redirects <= self._redirects):
                # Update connection with user specified request timeout,
                # the connect timeout is usually smaller so we only set
                # the request timeout after a connection is established
                if conn.sock is None:
                    conn.connect()
                    conn.sock.settimeout(self._http_timeout)
                elif conn.sock.gettimeout() != self._http_timeout:
                    conn.sock.settimeout(self._http_timeout)

                try:
                    conn.request(self._method, url, self._body, self._headers)
                except Exception, e:
                    LOG.info('_issue_request: conn.request() exception: %s' %
                             e)
                    raise e

                response = conn.getresponse()
                response.body = response.read()
                response.headers = response.getheaders()
                LOG.info("Request '%s' complete: %s (%0.2f seconds)"
                        % (self._request_str(conn, url), response.status,
                          time.time() - issued_time))
                if response.status not in [httplib.MOVED_PERMANENTLY,
                                           httplib.TEMPORARY_REDIRECT]:
                    break
                elif redirects >= self._redirects:
                    LOG.warn("Maximum redirects exceeded, aborting request")
                    break
                redirects += 1
                conn, url = self._redirect_params(conn, response.headers)
                if url is None:
                    response.status = httplib.INTERNAL_SERVER_ERROR
                    break
                LOG.info("Redirecting request to: %s" %
                         self._request_str(conn, url))

            # If we receive any of these responses, then our server did not
            # process our request and may be in an errored state. Raise an
            # exception, which will cause the the conn to be released with
            # is_conn_error == True which puts the conn on the back of the
            # client's priority queue.
            if response.status >= 500:
                LOG.warn("API Request '%s %s' received: %s" %
                         (self._method, self._url, response.status))
                raise Exception('Server error return: %s' %
                                response.status)
            return response
        except Exception, e:
            if isinstance(e, httplib.BadStatusLine):
                msg = "Invalid server response"
            else:
                msg = unicode(e)
            LOG.warn("Request '%s' failed: %s (%0.2f seconds)"
                     % (self._request_str(conn, url), msg,
                        time.time() - issued_time))
            self._request_error = e
            is_conn_error = True
            return e
        finally:
            self._api_client.release_connection(conn, is_conn_error)

    def _redirect_params(self, conn, headers):
        url = None
        for name, value in headers:
            if name.lower() == "location":
                url = value
                break
        if not url:
            LOG.warn("Received redirect status without location header field")
            return (conn, None)
        # Accept location with the following format:
        # 1. /path, redirect to same node
        # 2. scheme://hostname:[port]/path where scheme is https or http
        # Reject others
        # 3. e.g. relative paths, unsupported scheme, unspecified host
        result = urlparse.urlparse(url)
        if not result.scheme and not result.hostname and result.path:
            if result.path[0] == "/":
                if result.query:
                    url = "%s?%s" % (result.path, result.query)
                else:
                    url = result.path
                return (conn, url)      # case 1
            else:
                LOG.warn("Received invalid redirect location: %s" % url)
                return (conn, None)     # case 3
        elif result.scheme not in ["http", "https"] or not result.hostname:
            LOG.warn("Received malformed redirect location: %s" % url)
            return (conn, None)         # case 3
        # case 2, redirect location includes a scheme
        # so setup a new connection and authenticate
        use_https = result.scheme == "https"
        api_providers = [(result.hostname, result.port, use_https)]
        client_eventlet = (
            quantum.plugins.nicira.nicira_nvp_plugin.api_client.client_eventlet
            )
        api_client = client_eventlet.NvpApiClientEventlet(
            api_providers, self._api_client.user, self._api_client.password,
            use_https=use_https)
        api_client.wait_for_login()
        if api_client.auth_cookie:
            self._headers["Cookie"] = api_client.auth_cookie
        else:
            self._headers["Cookie"] = ""
        conn = api_client.acquire_connection()
        if result.query:
            url = "%s?%s" % (result.path, result.query)
        else:
            url = result.path
        return (conn, url)

    def _handle_request(self):
        attempt = 0
        response = None
        while response is None and attempt <= self._retries:
            attempt += 1

            if self._auto_login and self._api_client.need_login:
                self._api_client.wait_for_login()

            if self._api_client.auth_cookie and "Cookie" not in self._headers:
                self._headers["Cookie"] = self._api_client.auth_cookie

            req = self.spawn(self._issue_request).wait()
            # automatically raises any exceptions returned.
            LOG.debug('req: %s' % type(req))

            if isinstance(req, httplib.HTTPResponse):
                if (req.status == httplib.UNAUTHORIZED
                    or req.status == httplib.FORBIDDEN):
                    self._api_client.need_login = True
                    if attempt <= self._retries:
                        continue
                    # else fall through to return the error code

                LOG.debug("API Request '%s %s' complete: %s" %
                          (self._method, self._url, req.status))
                self._request_error = None
                response = req
            else:
                LOG.info('_handle_request: caught an error - %s' % req)
                self._request_error = req

        LOG.debug('_handle_request: response - %s' % response)
        return response


class NvpLoginRequestEventlet(NvpApiRequestEventlet):
    def __init__(self, nvp_client, user, password):
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        body = urllib.urlencode({"username": user, "password": password})
        NvpApiRequestEventlet.__init__(
            self, nvp_client, "/ws.v1/login", "POST", body, headers,
            auto_login=False)

    def session_cookie(self):
        if self.successful():
            return self.value.getheader("Set-Cookie")
        return None


class NvpGetApiProvidersRequestEventlet(NvpApiRequestEventlet):
    def __init__(self, nvp_client):
        url = "/ws.v1/control-cluster/node?fields=roles"
        NvpApiRequestEventlet.__init__(
            self, nvp_client, url, "GET", auto_login=True)

    def api_providers(self):
        """Parse api_providers from response.

        Returns: api_providers in [(host, port, is_ssl), ...] format
        """
        def _provider_from_listen_addr(addr):
            # (pssl|ptcp):<ip>:<port> => (host, port, is_ssl)
            parts = addr.split(':')
            return (parts[1], int(parts[2]), parts[0] == 'pssl')

        try:
            if self.successful():
                ret = []
                body = jsonutils.loads(self.value.body)
                for node in body.get('results', []):
                    for role in node.get('roles', []):
                        if role.get('role') == 'api_provider':
                            addr = role.get('listen_addr')
                            if addr:
                                ret.append(_provider_from_listen_addr(addr))
                return ret
        except Exception, e:
            LOG.warn("Failed to parse API provider: %s" % e)
            # intentionally fall through
        return None


class NvpGenericRequestEventlet(NvpApiRequestEventlet):
    def __init__(self, nvp_client, method, url, body, content_type,
                 auto_login=False,
                 request_timeout=DEFAULT_REQUEST_TIMEOUT,
                 http_timeout=DEFAULT_HTTP_TIMEOUT,
                 retries=DEFAULT_RETRIES,
                 redirects=DEFAULT_REDIRECTS):
        headers = {"Content-Type": content_type}

        NvpApiRequestEventlet.__init__(
            self, nvp_client, url, method, body, headers,
            request_timeout=request_timeout, retries=retries,
            auto_login=auto_login, redirects=redirects,
            http_timeout=http_timeout)

    def session_cookie(self):
        if self.successful():
            return self.value.getheader("Set-Cookie")
        return None


# Register subclasses
request.NvpApiRequest.register(NvpApiRequestEventlet)
