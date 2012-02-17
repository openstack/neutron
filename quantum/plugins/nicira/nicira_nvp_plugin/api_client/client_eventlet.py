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


import client
import eventlet
import httplib
import logging
import request_eventlet
import time
from common import _conn_str


logging.basicConfig(level=logging.INFO)
lg = logging.getLogger('nvp_api_client')

# Default parameters.
DEFAULT_FAILOVER_TIME = 5
DEFAULT_CONCURRENT_CONNECTIONS = 3
DEFAULT_CONNECT_TIMEOUT = 5


class NvpApiClientEventlet(object):
    '''Eventlet-based implementation of NvpApiClient ABC.'''

    CONN_IDLE_TIMEOUT = 60 * 15

    def __init__(self, api_providers, user, password,
                 concurrent_connections=DEFAULT_CONCURRENT_CONNECTIONS,
                 use_https=True,
                 connect_timeout=DEFAULT_CONNECT_TIMEOUT,
                 failover_time=DEFAULT_FAILOVER_TIME):
        '''Constructor

        Args:
            api_providers: a list of tuples of the form: (host, port, is_ssl).
            user: login username.
            password: login password.
            concurrent_connections: total number of concurrent connections.
            use_https: whether or not to use https for requests.
            connect_timeout: connection timeout in seconds.
        '''
        self._api_providers = set([tuple(p) for p in api_providers])
        self._user = user
        self._password = password
        self._concurrent_connections = concurrent_connections
        self._use_https = use_https
        self._connect_timeout = connect_timeout
        self._failover_time = failover_time

        # Connection pool is a queue. Head of the queue is the
        # connection pool with the highest priority.
        self._conn_pool = eventlet.queue.Queue()
        for host, port, is_ssl in self._api_providers:
            provider_conn_pool = eventlet.queue.Queue()
            for i in range(concurrent_connections):
                # All connections in a provider_conn_poool have the
                # same priority (they connect to the same server).
                conn = self._create_connection(host, port, is_ssl)
                conn.conn_pool = provider_conn_pool
                provider_conn_pool.put(conn)

            self._conn_pool.put(provider_conn_pool)

        self._active_conn_pool = self._conn_pool.get()

        self._cookie = None
        self._need_login = True
        self._doing_login_sem = eventlet.semaphore.Semaphore(1)

    def _create_connection(self, host, port, is_ssl):
        if is_ssl:
            return httplib.HTTPSConnection(host, port,
                                           timeout=self._connect_timeout)
        return httplib.HTTPConnection(host, port,
                                      timeout=self._connect_timeout)

    @staticmethod
    def _conn_params(http_conn):
        is_ssl = isinstance(http_conn, httplib.HTTPSConnection)
        return (http_conn.host, http_conn.port, is_ssl)

    def update_providers(self, api_providers):
        raise Exception('update_providers() not implemented.')

    @property
    def user(self):
        return self._user

    @property
    def password(self):
        return self._password

    @property
    def auth_cookie(self):
        return self._cookie

    def acquire_connection(self):
        '''Check out an available HTTPConnection instance.

        Blocks until a connection is available.

        Returns: An available HTTPConnection instance or None if no
                 api_providers are configured.
        '''
        if not self._api_providers:
            return None

        # The sleep time is to give controllers time to become consistent after
        # there has been a change in the controller used as the api_provider.
        now = time.time()
        if now < getattr(self, '_issue_conn_barrier', now):
            lg.info("acquire_connection() waiting for timer to expire.")
            time.sleep(self._issue_conn_barrier - now)

        if self._active_conn_pool.empty():
            lg.debug("Waiting to acquire an API client connection")

        # get() call is blocking.
        conn = self._active_conn_pool.get()
        now = time.time()
        if getattr(conn, 'last_used', now) < now - self.CONN_IDLE_TIMEOUT:
            lg.info("Connection %s idle for %0.2f seconds; reconnecting."
                    % (_conn_str(conn), now - conn.last_used))
            conn = self._create_connection(*self._conn_params(conn))

            # Stash conn pool so conn knows where to go when it releases.
            conn.conn_pool = self._active_conn_pool

        conn.last_used = now
        lg.debug("API client connection %s acquired" % _conn_str(conn))
        return conn

    def release_connection(self, http_conn, bad_state=False):
        '''Mark HTTPConnection instance as available for check-out.

        Args:
            http_conn: An HTTPConnection instance obtained from this
                instance.
            bad_state: True if http_conn is known to be in a bad state
                (e.g. connection fault.)
        '''
        if self._conn_params(http_conn) not in self._api_providers:
            lg.debug("Released connection '%s' is no longer an API provider "
                     "for the cluster" % _conn_str(http_conn))
            return

        # Retrieve "home" connection pool.
        conn_pool = http_conn.conn_pool
        if bad_state:
            # reconnect
            lg.info("API connection fault, reconnecting to %s"
                    % _conn_str(http_conn))
            http_conn = self._create_connection(*self._conn_params(http_conn))
            http_conn.conn_pool = conn_pool
            conn_pool.put(http_conn)

            if self._active_conn_pool == http_conn.conn_pool:
                # Get next connection from the connection pool and make it
                # active.
                lg.info("API connection fault changing active_conn_pool.")
                self._conn_pool.put(self._active_conn_pool)
                self._active_conn_pool = self._conn_pool.get()
                self._issue_conn_barrier = time.time() + self._failover_time
        else:
            conn_pool.put(http_conn)

        lg.debug("API client connection %s released" % _conn_str(http_conn))

    @property
    def need_login(self):
        return self._need_login

    @need_login.setter
    def need_login(self, val=True):
        self._need_login = val

    def wait_for_login(self):
        if self._need_login:
            if self._doing_login_sem.acquire(blocking=False):
                self.login()
                self._doing_login_sem.release()
            else:
                lg.debug("Waiting for auth to complete")
                self._doing_login_sem.acquire()
                self._doing_login_sem.release()
        return self._cookie

    def login(self):
        '''Issue login request and update authentication cookie.'''
        g = request_eventlet.NvpLoginRequestEventlet(
            self, self._user, self._password)
        g.start()
        ret = g.join()

        if ret:
            if isinstance(ret, Exception):
                lg.error('NvpApiClient: login error "%s"' % ret)
                raise ret

            self._cookie = None
            cookie = ret.getheader("Set-Cookie")
            if cookie:
                lg.debug("Saving new authentication cookie '%s'" % cookie)
                self._cookie = cookie
                self._need_login = False

        if not ret:
            return None

        return self._cookie


# Register as subclass.
client.NvpApiClient.register(NvpApiClientEventlet)
