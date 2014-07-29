# Copyright 2012 VMware, Inc.
#
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import eventlet
import httplib
import json
import urllib

from neutron.openstack.common import log as logging
from neutron.plugins.vmware.api_client import request

LOG = logging.getLogger(__name__)
USER_AGENT = "Neutron eventlet client/2.0"


class EventletApiRequest(request.ApiRequest):
    '''Eventlet-based ApiRequest class.

    This class will form the basis for eventlet-based ApiRequest classes
    '''

    # Maximum number of green threads present in the system at one time.
    API_REQUEST_POOL_SIZE = request.DEFAULT_API_REQUEST_POOL_SIZE

    # Pool of green threads. One green thread is allocated per incoming
    # request. Incoming requests will block when the pool is empty.
    API_REQUEST_POOL = eventlet.GreenPool(API_REQUEST_POOL_SIZE)

    # A unique id is assigned to each incoming request. When the current
    # request id reaches MAXIMUM_REQUEST_ID it wraps around back to 0.
    MAXIMUM_REQUEST_ID = request.DEFAULT_MAXIMUM_REQUEST_ID

    # The request id for the next incoming request.
    CURRENT_REQUEST_ID = 0

    def __init__(self, client_obj, url, method="GET", body=None,
                 headers=None,
                 request_timeout=request.DEFAULT_REQUEST_TIMEOUT,
                 retries=request.DEFAULT_RETRIES,
                 auto_login=True,
                 redirects=request.DEFAULT_REDIRECTS,
                 http_timeout=request.DEFAULT_HTTP_TIMEOUT, client_conn=None):
        '''Constructor.'''
        self._api_client = client_obj
        self._url = url
        self._method = method
        self._body = body
        self._headers = headers or {}
        self._request_timeout = request_timeout
        self._retries = retries
        self._auto_login = auto_login
        self._redirects = redirects
        self._http_timeout = http_timeout
        self._client_conn = client_conn
        self._abort = False

        self._request_error = None

        if "User-Agent" not in self._headers:
            self._headers["User-Agent"] = USER_AGENT

        self._green_thread = None
        # Retrieve and store this instance's unique request id.
        self._request_id = EventletApiRequest.CURRENT_REQUEST_ID
        # Update the class variable that tracks request id.
        # Request IDs wrap around at MAXIMUM_REQUEST_ID
        next_request_id = self._request_id + 1
        next_request_id %= self.MAXIMUM_REQUEST_ID
        EventletApiRequest.CURRENT_REQUEST_ID = next_request_id

    @classmethod
    def _spawn(cls, func, *args, **kwargs):
        '''Allocate a green thread from the class pool.'''
        return cls.API_REQUEST_POOL.spawn(func, *args, **kwargs)

    def spawn(self, func, *args, **kwargs):
        '''Spawn a new green thread with the supplied function and args.'''
        return self.__class__._spawn(func, *args, **kwargs)

    @classmethod
    def joinall(cls):
        '''Wait for all outstanding requests to complete.'''
        return cls.API_REQUEST_POOL.waitall()

    def join(self):
        '''Wait for instance green thread to complete.'''
        if self._green_thread is not None:
            return self._green_thread.wait()
        return Exception(_('Joining an invalid green thread'))

    def start(self):
        '''Start request processing.'''
        self._green_thread = self.spawn(self._run)

    def copy(self):
        '''Return a copy of this request instance.'''
        return EventletApiRequest(
            self._api_client, self._url, self._method, self._body,
            self._headers, self._request_timeout, self._retries,
            self._auto_login, self._redirects, self._http_timeout)

    def _run(self):
        '''Method executed within green thread.'''
        if self._request_timeout:
            # No timeout exception escapes the with block.
            with eventlet.timeout.Timeout(self._request_timeout, False):
                return self._handle_request()

            LOG.info(_('[%d] Request timeout.'), self._rid())
            self._request_error = Exception(_('Request timeout'))
            return None
        else:
            return self._handle_request()

    def _handle_request(self):
        '''First level request handling.'''
        attempt = 0
        timeout = 0
        response = None
        while response is None and attempt <= self._retries:
            eventlet.greenthread.sleep(timeout)
            attempt += 1

            req = self._issue_request()
            # automatically raises any exceptions returned.
            if isinstance(req, httplib.HTTPResponse):
                timeout = 0
                if attempt <= self._retries and not self._abort:
                    if req.status in (httplib.UNAUTHORIZED, httplib.FORBIDDEN):
                        continue
                    elif req.status == httplib.SERVICE_UNAVAILABLE:
                        timeout = 0.5
                        continue
                    # else fall through to return the error code

                LOG.debug(_("[%(rid)d] Completed request '%(method)s %(url)s'"
                            ": %(status)s"),
                          {'rid': self._rid(), 'method': self._method,
                           'url': self._url, 'status': req.status})
                self._request_error = None
                response = req
            else:
                LOG.info(_('[%(rid)d] Error while handling request: %(req)s'),
                         {'rid': self._rid(), 'req': req})
                self._request_error = req
                response = None
        return response


class LoginRequestEventlet(EventletApiRequest):
    '''Process a login request.'''

    def __init__(self, client_obj, user, password, client_conn=None,
                 headers=None):
        if headers is None:
            headers = {}
        headers.update({"Content-Type": "application/x-www-form-urlencoded"})
        body = urllib.urlencode({"username": user, "password": password})
        super(LoginRequestEventlet, self).__init__(
            client_obj, "/ws.v1/login", "POST", body, headers,
            auto_login=False, client_conn=client_conn)

    def session_cookie(self):
        if self.successful():
            return self.value.getheader("Set-Cookie")
        return None


class GetApiProvidersRequestEventlet(EventletApiRequest):
    '''Get a list of API providers.'''

    def __init__(self, client_obj):
        url = "/ws.v1/control-cluster/node?fields=roles"
        super(GetApiProvidersRequestEventlet, self).__init__(
            client_obj, url, "GET", auto_login=True)

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
            LOG.warn(_("[%(rid)d] Failed to parse API provider: %(e)s"),
                     {'rid': self._rid(), 'e': e})
            # intentionally fall through
        return None


class GenericRequestEventlet(EventletApiRequest):
    '''Handle a generic request.'''

    def __init__(self, client_obj, method, url, body, content_type,
                 auto_login=False,
                 request_timeout=request.DEFAULT_REQUEST_TIMEOUT,
                 http_timeout=request.DEFAULT_HTTP_TIMEOUT,
                 retries=request.DEFAULT_RETRIES,
                 redirects=request.DEFAULT_REDIRECTS):
        headers = {"Content-Type": content_type}
        super(GenericRequestEventlet, self).__init__(
            client_obj, url, method, body, headers,
            request_timeout=request_timeout, retries=retries,
            auto_login=auto_login, redirects=redirects,
            http_timeout=http_timeout)

    def session_cookie(self):
        if self.successful():
            return self.value.getheader("Set-Cookie")
        return None


request.ApiRequest.register(EventletApiRequest)
