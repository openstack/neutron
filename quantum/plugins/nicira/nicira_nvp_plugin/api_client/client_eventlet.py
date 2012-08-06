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

import client
import eventlet
import httplib
import logging
import request_eventlet
import time

from common import _conn_str

eventlet.monkey_patch()

logging.basicConfig(level=logging.INFO)
lg = logging.getLogger('nvp_api_client')

# Default parameters.
DEFAULT_FAILOVER_TIME = 5
DEFAULT_CONCURRENT_CONNECTIONS = 3
DEFAULT_CONNECT_TIMEOUT = 5
GENERATION_ID_TIMEOUT = -1  # if set to -1 then disabled


class NvpApiClientEventlet(object):
    '''Eventlet-based implementation of NvpApiClient ABC.'''

    CONN_IDLE_TIMEOUT = 60 * 15

    def __init__(self, api_providers, user, password,
                 concurrent_connections=DEFAULT_CONCURRENT_CONNECTIONS,
                 use_https=True,
                 connect_timeout=DEFAULT_CONNECT_TIMEOUT,
                 failover_time=DEFAULT_FAILOVER_TIME,
                 nvp_gen_timeout=GENERATION_ID_TIMEOUT):
        '''Constructor

        :param api_providers: a list of tuples of the form: (host, port,
            is_ssl).
        :param user: login username.
        :param password: login password.
        :param concurrent_connections: total number of concurrent connections.
        :param use_https: whether or not to use https for requests.
        :param connect_timeout: connection timeout in seconds.
        :param failover_time: time from when a connection pool is switched to
            the next connection released via acquire_connection().
        :param nvp_gen_timeout controls how long the generation id is kept
            if set to -1 the generation id is never timed out
        '''
        if not api_providers:
            api_providers = []
        self._api_providers = set([tuple(p) for p in api_providers])
        self._user = user
        self._password = password
        self._concurrent_connections = concurrent_connections
        self._use_https = use_https
        self._connect_timeout = connect_timeout
        self._failover_time = failover_time
        self._nvp_config_gen = None
        self._nvp_config_gen_ts = None
        self._nvp_gen_timeout = nvp_gen_timeout

        # Connection pool is a list of queues.
        self._conn_pool = list()
        conn_pool_idx = 0
        for host, port, is_ssl in api_providers:
            provider_conn_pool = eventlet.queue.Queue(
                maxsize=concurrent_connections)
            for i in range(concurrent_connections):
                # All connections in a provider_conn_poool have the
                # same priority (they connect to the same server).
                conn = self._create_connection(host, port, is_ssl)
                conn.idx = conn_pool_idx
                provider_conn_pool.put(conn)

            self._conn_pool.append(provider_conn_pool)
            conn_pool_idx += 1

        self._active_conn_pool_idx = 0

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
    def nvp_config_gen(self):
        # If nvp_gen_timeout is not -1 then:
        # Maintain a timestamp along with the generation ID.  Hold onto the
        # ID long enough to be useful and block on sequential requests but
        # not long enough to persist when Onix db is cleared, which resets
        # the generation ID, causing the DAL to block indefinitely with some
        # number that's higher than the cluster's value.
        if self._nvp_gen_timeout != -1:
            ts = self._nvp_config_gen_ts
            if ts is not None:
                if (time.time() - ts) > self._nvp_gen_timeout:
                    return None
        return self._nvp_config_gen

    @nvp_config_gen.setter
    def nvp_config_gen(self, value):
        if self._nvp_config_gen != value:
            if self._nvp_gen_timeout != -1:
                self._nvp_config_gen_ts = time.time()
        self._nvp_config_gen = value

    @property
    def auth_cookie(self):
        return self._cookie

    def acquire_connection(self, rid=-1):
        '''Check out an available HTTPConnection instance.

        Blocks until a connection is available.

        :param rid: request id passed in from request eventlet.
        :returns: An available HTTPConnection instance or None if no
                 api_providers are configured.
        '''
        if not self._api_providers:
            lg.warn("[%d] no API providers currently available." % rid)
            return None

        # The sleep time is to give controllers time to become consistent after
        # there has been a change in the controller used as the api_provider.
        now = time.time()
        if now < getattr(self, '_issue_conn_barrier', now):
            lg.warn("[%d] Waiting for failover timer to expire." % rid)
            time.sleep(self._issue_conn_barrier - now)

        # Print out a warning if all connections are in use.
        if self._conn_pool[self._active_conn_pool_idx].empty():
            lg.debug("[%d] Waiting to acquire client connection." % rid)

        # Try to acquire a connection (block in get() until connection
        # available or timeout occurs).
        active_conn_pool_idx = self._active_conn_pool_idx
        conn = self._conn_pool[active_conn_pool_idx].get()

        if active_conn_pool_idx != self._active_conn_pool_idx:
            # active_conn_pool became inactive while we were waiting.
            # Put connection back on old pool and try again.
            lg.warn("[%d] Active pool expired while waiting for connection: %s"
                    % (rid, _conn_str(conn)))
            self._conn_pool[active_conn_pool_idx].put(conn)
            return self.acquire_connection(rid=rid)

        # Check if the connection has been idle too long.
        now = time.time()
        if getattr(conn, 'last_used', now) < now - self.CONN_IDLE_TIMEOUT:
            lg.info("[%d] Connection %s idle for %0.2f seconds; reconnecting."
                    % (rid, _conn_str(conn), now - conn.last_used))
            conn = self._create_connection(*self._conn_params(conn))

            # Stash conn pool so conn knows where to go when it releases.
            conn.idx = self._active_conn_pool_idx

        conn.last_used = now
        qsize = self._conn_pool[self._active_conn_pool_idx].qsize()
        lg.debug("[%d] Acquired connection %s. %d connection(s) available."
                 % (rid, _conn_str(conn), qsize))
        return conn

    def release_connection(self, http_conn, bad_state=False, rid=-1):
        '''Mark HTTPConnection instance as available for check-out.

        :param http_conn: An HTTPConnection instance obtained from this
            instance.
        :param bad_state: True if http_conn is known to be in a bad state
                (e.g. connection fault.)
        :param rid: request id passed in from request eventlet.
        '''
        if self._conn_params(http_conn) not in self._api_providers:
            lg.warn("[%d] Released connection '%s' is not an API provider "
                    "for the cluster" % (rid, _conn_str(http_conn)))
            return

        # Retrieve "home" connection pool.
        conn_pool_idx = http_conn.idx
        conn_pool = self._conn_pool[conn_pool_idx]
        if bad_state:
            # Reconnect to provider.
            lg.warn("[%d] Connection returned in bad state, reconnecting to %s"
                    % (rid, _conn_str(http_conn)))
            http_conn = self._create_connection(*self._conn_params(http_conn))
            http_conn.idx = conn_pool_idx

            if self._active_conn_pool_idx == http_conn.idx:
                # This pool is no longer in a good state. Switch to next pool.
                self._active_conn_pool_idx += 1
                self._active_conn_pool_idx %= len(self._conn_pool)
                lg.warn("[%d] Switched active_conn_pool from %d to %d."
                        % (rid, http_conn.idx, self._active_conn_pool_idx))

                # No connections to the new provider allowed until after this
                # timer has expired (allow time for synchronization).
                self._issue_conn_barrier = time.time() + self._failover_time

        conn_pool.put(http_conn)
        lg.debug("[%d] Released connection %s. %d connection(s) available."
                 % (rid, _conn_str(http_conn), conn_pool.qsize()))

    @property
    def need_login(self):
        return self._need_login

    @need_login.setter
    def need_login(self, val=True):
        self._need_login = val

    def wait_for_login(self):
        '''Block until a login has occurred for the current API provider.'''
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

        # TODO: or ret is an error.
        if not ret:
            return None

        return self._cookie


# Register as subclass.
client.NvpApiClient.register(NvpApiClientEventlet)
