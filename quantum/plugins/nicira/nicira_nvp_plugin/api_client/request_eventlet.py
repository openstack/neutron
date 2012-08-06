# Copyright 2009-2012 Nicira Networks, Inc.
# All Rights Reserved
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
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#

import copy
import eventlet
import httplib
import json
import logging
import urllib
import urlparse
import request
import time

import client_eventlet
from common import _conn_str
from eventlet import timeout

eventlet.monkey_patch()

logging.basicConfig(level=logging.INFO)
lg = logging.getLogger("nvp_api_request")
USER_AGENT = "NVP eventlet client/1.0"

# Default parameters.
DEFAULT_REQUEST_TIMEOUT = 30
DEFAULT_HTTP_TIMEOUT = 10
DEFAULT_RETRIES = 2
DEFAULT_REDIRECTS = 2
DEFAULT_API_REQUEST_POOL_SIZE = 1000
DEFAULT_MAXIMUM_REQUEST_ID = 4294967295


class NvpApiRequestEventlet:
    '''Eventlet-based ApiRequest class.

    This class will form the basis for eventlet-based ApiRequest classes
    (e.g. those used by the Quantum NVP Plugin).
    '''

    # List of allowed status codes.
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
        httplib.SERVICE_UNAVAILABLE
    ]

    # Maximum number of green threads present in the system at one time.
    API_REQUEST_POOL_SIZE = DEFAULT_API_REQUEST_POOL_SIZE

    # Pool of green threads. One green thread is allocated per incoming
    # request. Incoming requests will block when the pool is empty.
    API_REQUEST_POOL = eventlet.GreenPool(API_REQUEST_POOL_SIZE)

    # A unique id is assigned to each incoming request. When the current
    # request id reaches MAXIMUM_REQUEST_ID it wraps around back to 0.
    MAXIMUM_REQUEST_ID = DEFAULT_MAXIMUM_REQUEST_ID

    # The request id for the next incoming request.
    CURRENT_REQUEST_ID = 0

    def __init__(self, nvp_api_client, url, method="GET", body=None,
                 headers=None,
                 request_timeout=DEFAULT_REQUEST_TIMEOUT,
                 retries=DEFAULT_RETRIES,
                 auto_login=True,
                 redirects=DEFAULT_REDIRECTS,
                 http_timeout=DEFAULT_HTTP_TIMEOUT):
        '''Constructor.'''
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

        # Retrieve and store this instance's unique request id.
        self._request_id = NvpApiRequestEventlet.CURRENT_REQUEST_ID

        # Update the class variable that tracks request id.
        # Request IDs wrap around at MAXIMUM_REQUEST_ID
        next_request_id = self._request_id + 1
        next_request_id %= NvpApiRequestEventlet.MAXIMUM_REQUEST_ID
        NvpApiRequestEventlet.CURRENT_REQUEST_ID = next_request_id

    @classmethod
    def _spawn(cls, func, *args, **kwargs):
        '''Allocate a green thread from the class pool.'''
        return cls.API_REQUEST_POOL.spawn(func, *args, **kwargs)

    def spawn(self, func, *args, **kwargs):
        '''Spawn a new green thread with the supplied function and args.'''
        return self.__class__._spawn(func, *args, **kwargs)

    def _rid(self):
        '''Return current request id.'''
        return self._request_id

    @classmethod
    def joinall(cls):
        '''Wait for all outstanding requests to complete.'''
        return cls.API_REQUEST_POOL.waitall()

    def join(self):
        '''Wait for instance green thread to complete.'''
        if self._green_thread is not None:
            return self._green_thread.wait()
        return Exception('Joining an invalid green thread')

    def start(self):
        '''Start request processing.'''
        self._green_thread = self.spawn(self._run)

    def copy(self):
        '''Return a copy of this request instance.'''
        return NvpApiRequestEventlet(
            self._api_client, self._url, self._method, self._body,
            self._headers, self._request_timeout, self._retries,
            self._auto_login, self._redirects, self._http_timeout)

    @property
    def request_error(self):
        '''Return any errors associated with this instance.'''
        return self._request_error

    def _run(self):
        '''Method executed within green thread.'''
        if self._request_timeout:
            # No timeout exception escapes the with block.
            with timeout.Timeout(self._request_timeout, False):
                return self._handle_request()

            lg.info('[%d] Request timeout.' % self._rid())
            self._request_error = Exception('Request timeout')
            return None
        else:
            return self._handle_request()

    def _request_str(self, conn, url):
        '''Return string representation of connection.'''
        return "%s %s/%s" % (self._method, _conn_str(conn), url)

    def _issue_request(self):
        '''Issue a request to a provider.'''
        conn = self._api_client.acquire_connection(rid=self._rid())
        if conn is None:
            error = Exception("No API connections available")
            self._request_error = error
            return error

        # Preserve the acquired connection as conn may be over-written by
        # redirects below.
        acquired_conn = conn

        url = self._url
        lg.debug("[%d] Issuing - request '%s'" %
                 (self._rid(),
                 self._request_str(conn, url)))
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

                headers = copy.copy(self._headers)
                gen = self._api_client.nvp_config_gen
                if gen:
                    headers["X-Nvp-Wait-For-Config-Generation"] = gen
                    lg.debug("Setting %s request header: %s" %
                             ('X-Nvp-Wait-For-Config-Generation', gen))
                try:
                    conn.request(self._method, url, self._body, headers)
                except Exception as e:
                    lg.warn('[%d] Exception issuing request: %s' %
                            (self._rid(), e))
                    raise e

                response = conn.getresponse()
                response.body = response.read()
                response.headers = response.getheaders()
                lg.debug("[%d] Completed request '%s': %s (%0.2f seconds)"
                         % (self._rid(), self._request_str(conn, url),
                            response.status, time.time() - issued_time))

                new_gen = response.getheader('X-Nvp-Config-Generation', None)
                if new_gen:
                    lg.debug("Reading %s response header: %s" %
                             ('X-Nvp-config-Generation', new_gen))
                    if (self._api_client.nvp_config_gen is None or
                            self._api_client.nvp_config_gen < int(new_gen)):
                        self._api_client.nvp_config_gen = int(new_gen)

                if response.status not in [httplib.MOVED_PERMANENTLY,
                                           httplib.TEMPORARY_REDIRECT]:
                    break
                elif redirects >= self._redirects:
                    lg.info("[%d] Maximum redirects exceeded, aborting request"
                            % self._rid())
                    break
                redirects += 1

                # In the following call, conn is replaced by the connection
                # specified in the redirect response from the server.
                conn, url = self._redirect_params(conn, response.headers)
                if url is None:
                    response.status = httplib.INTERNAL_SERVER_ERROR
                    break
                lg.info("[%d] Redirecting request to: %s" %
                        (self._rid(), self._request_str(conn, url)))

            # FIX for #9415. If we receive any of these responses, then
            # our server did not process our request and may be in an
            # errored state. Raise an exception, which will cause the
            # the conn to be released with is_conn_error == True
            # which puts the conn on the back of the client's priority
            # queue.
            if response.status >= 500:
                lg.warn("[%d] Request '%s %s' received: %s"
                        % (self._rid(), self._method, self._url,
                           response.status))
                raise Exception('Server error return: %s' %
                                response.status)
            return response
        except Exception as e:
            if isinstance(e, httplib.BadStatusLine):
                msg = "Invalid server response"
            else:
                msg = unicode(e)
            lg.warn("[%d] Failed request '%s': %s (%0.2f seconds)"
                    % (self._rid(), self._request_str(conn, url), msg,
                       time.time() - issued_time))
            self._request_error = e
            is_conn_error = True
            return e
        finally:
            # Make sure we release the original connection provided by the
            # acquire_connection() call above.
            self._api_client.release_connection(acquired_conn, is_conn_error,
                                                rid=self._rid())

    def _redirect_params(self, conn, headers):
        '''Process redirect params from a server response.'''
        url = None
        for name, value in headers:
            if name.lower() == "location":
                url = value
                break
        if not url:
            lg.warn("[%d] Received redirect status without location header"
                    " field" % self._rid())
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
                lg.warn("[%d] Received invalid redirect location: %s" %
                        (self._rid(), url))
                return (conn, None)     # case 3
        elif result.scheme not in ["http", "https"] or not result.hostname:
            lg.warn("[%d] Received malformed redirect location: %s" %
                    (self._rid(), url))
            return (conn, None)         # case 3
        # case 2, redirect location includes a scheme
        # so setup a new connection and authenticate
        use_https = result.scheme == "https"
        api_providers = [(result.hostname, result.port, use_https)]
        api_client = client_eventlet.NvpApiClientEventlet(
            api_providers, self._api_client.user, self._api_client.password,
            use_https=use_https)
        api_client.wait_for_login()
        if api_client.auth_cookie:
            self._headers["Cookie"] = api_client.auth_cookie
        else:
            self._headers["Cookie"] = ""
        conn = api_client.acquire_connection(rid=self._rid())
        if result.query:
            url = "%s?%s" % (result.path, result.query)
        else:
            url = result.path
        return (conn, url)

    def _handle_request(self):
        '''First level request handling.'''
        attempt = 0
        response = None
        while response is None and attempt <= self._retries:
            attempt += 1

            if self._auto_login and self._api_client.need_login:
                self._api_client.wait_for_login()

            if self._api_client.auth_cookie:
                self._headers["Cookie"] = self._api_client.auth_cookie

            req = self.spawn(self._issue_request).wait()
            # automatically raises any exceptions returned.
            if isinstance(req, httplib.HTTPResponse):
                if (req.status == httplib.UNAUTHORIZED
                        or req.status == httplib.FORBIDDEN):
                    self._api_client.need_login = True
                    if attempt <= self._retries:
                        continue
                    # else fall through to return the error code

                lg.debug("[%d] Completed request '%s %s': %s"
                         % (self._rid(), self._method, self._url, req.status))
                self._request_error = None
                response = req
            else:
                lg.info('[%d] Error while handling request: %s' % (self._rid(),
                                                                   req))
                self._request_error = req
                response = None

        return response


class NvpLoginRequestEventlet(NvpApiRequestEventlet):
    '''Process a login request.'''

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
    '''Get a list of API providers.'''

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
                body = json.loads(self.value.body)
                for node in body.get('results', []):
                    for role in node.get('roles', []):
                        if role.get('role') == 'api_provider':
                            addr = role.get('listen_addr')
                            if addr:
                                ret.append(_provider_from_listen_addr(addr))
                return ret
        except Exception as e:
            lg.warn("[%d] Failed to parse API provider: %s" % (self._rid(), e))
            # intentionally fall through
        return None


class NvpGenericRequestEventlet(NvpApiRequestEventlet):
    '''Handle a generic request.'''

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
