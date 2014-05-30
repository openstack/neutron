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
#

import time

import eventlet
eventlet.monkey_patch()

from neutron.openstack.common import log as logging
from neutron.plugins.vmware.api_client import base
from neutron.plugins.vmware.api_client import eventlet_request

LOG = logging.getLogger(__name__)


class EventletApiClient(base.ApiClientBase):
    """Eventlet-based implementation of NSX ApiClient ABC."""

    def __init__(self, api_providers, user, password,
                 concurrent_connections=base.DEFAULT_CONCURRENT_CONNECTIONS,
                 gen_timeout=base.GENERATION_ID_TIMEOUT,
                 use_https=True,
                 connect_timeout=base.DEFAULT_CONNECT_TIMEOUT):
        '''Constructor

        :param api_providers: a list of tuples of the form: (host, port,
            is_ssl).
        :param user: login username.
        :param password: login password.
        :param concurrent_connections: total number of concurrent connections.
        :param use_https: whether or not to use https for requests.
        :param connect_timeout: connection timeout in seconds.
        :param gen_timeout controls how long the generation id is kept
            if set to -1 the generation id is never timed out
        '''
        if not api_providers:
            api_providers = []
        self._api_providers = set([tuple(p) for p in api_providers])
        self._api_provider_data = {}  # tuple(semaphore, session_cookie)
        for p in self._api_providers:
            self._set_provider_data(p, (eventlet.semaphore.Semaphore(1), None))
        self._user = user
        self._password = password
        self._concurrent_connections = concurrent_connections
        self._use_https = use_https
        self._connect_timeout = connect_timeout
        self._config_gen = None
        self._config_gen_ts = None
        self._gen_timeout = gen_timeout

        # Connection pool is a list of queues.
        self._conn_pool = eventlet.queue.PriorityQueue()
        self._next_conn_priority = 1
        for host, port, is_ssl in api_providers:
            for _ in range(concurrent_connections):
                conn = self._create_connection(host, port, is_ssl)
                self._conn_pool.put((self._next_conn_priority, conn))
                self._next_conn_priority += 1

    def acquire_redirect_connection(self, conn_params, auto_login=True,
                                    headers=None):
        """Check out or create connection to redirected NSX API server.

        Args:
            conn_params: tuple specifying target of redirect, see
                self._conn_params()
            auto_login: returned connection should have valid session cookie
            headers: headers to pass on if auto_login

        Returns: An available HTTPConnection instance corresponding to the
                 specified conn_params. If a connection did not previously
                 exist, new connections are created with the highest prioity
                 in the connection pool and one of these new connections
                 returned.
        """
        result_conn = None
        data = self._get_provider_data(conn_params)
        if data:
            # redirect target already exists in provider data and connections
            # to the provider have been added to the connection pool. Try to
            # obtain a connection from the pool, note that it's possible that
            # all connection to the provider are currently in use.
            conns = []
            while not self._conn_pool.empty():
                priority, conn = self._conn_pool.get_nowait()
                if not result_conn and self._conn_params(conn) == conn_params:
                    conn.priority = priority
                    result_conn = conn
                else:
                    conns.append((priority, conn))
            for priority, conn in conns:
                self._conn_pool.put((priority, conn))
            # hack: if no free connections available, create new connection
            # and stash "no_release" attribute (so that we only exceed
            # self._concurrent_connections temporarily)
            if not result_conn:
                conn = self._create_connection(*conn_params)
                conn.priority = 0  # redirect connections have highest priority
                conn.no_release = True
                result_conn = conn
        else:
            #redirect target not already known, setup provider lists
            self._api_providers.update([conn_params])
            self._set_provider_data(conn_params,
                                    (eventlet.semaphore.Semaphore(1), None))
            # redirects occur during cluster upgrades, i.e. results to old
            # redirects to new, so give redirect targets highest priority
            priority = 0
            for i in range(self._concurrent_connections):
                conn = self._create_connection(*conn_params)
                conn.priority = priority
                if i == self._concurrent_connections - 1:
                    break
                self._conn_pool.put((priority, conn))
            result_conn = conn
        if result_conn:
            result_conn.last_used = time.time()
            if auto_login and self.auth_cookie(conn) is None:
                self._wait_for_login(result_conn, headers)
        return result_conn

    def _login(self, conn=None, headers=None):
        '''Issue login request and update authentication cookie.'''
        cookie = None
        g = eventlet_request.LoginRequestEventlet(
            self, self._user, self._password, conn, headers)
        g.start()
        ret = g.join()
        if ret:
            if isinstance(ret, Exception):
                LOG.error(_('Login error "%s"'), ret)
                raise ret

            cookie = ret.getheader("Set-Cookie")
            if cookie:
                LOG.debug(_("Saving new authentication cookie '%s'"), cookie)

        return cookie

# Register as subclass.
base.ApiClientBase.register(EventletApiClient)
