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

import abc
import httplib
import six
import time

from oslo_config import cfg

from neutron.i18n import _LE, _LI, _LW
from neutron.openstack.common import log as logging
from neutron.plugins.vmware import api_client

LOG = logging.getLogger(__name__)

GENERATION_ID_TIMEOUT = -1
DEFAULT_CONCURRENT_CONNECTIONS = 3
DEFAULT_CONNECT_TIMEOUT = 5


@six.add_metaclass(abc.ABCMeta)
class ApiClientBase(object):
    """An abstract baseclass for all API client implementations."""

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

    @property
    def user(self):
        return self._user

    @property
    def password(self):
        return self._password

    @property
    def config_gen(self):
        # If NSX_gen_timeout is not -1 then:
        # Maintain a timestamp along with the generation ID.  Hold onto the
        # ID long enough to be useful and block on sequential requests but
        # not long enough to persist when Onix db is cleared, which resets
        # the generation ID, causing the DAL to block indefinitely with some
        # number that's higher than the cluster's value.
        if self._gen_timeout != -1:
            ts = self._config_gen_ts
            if ts is not None:
                if (time.time() - ts) > self._gen_timeout:
                    return None
        return self._config_gen

    @config_gen.setter
    def config_gen(self, value):
        if self._config_gen != value:
            if self._gen_timeout != -1:
                self._config_gen_ts = time.time()
        self._config_gen = value

    def auth_cookie(self, conn):
        cookie = None
        data = self._get_provider_data(conn)
        if data:
            cookie = data[1]
        return cookie

    def set_auth_cookie(self, conn, cookie):
        data = self._get_provider_data(conn)
        if data:
            self._set_provider_data(conn, (data[0], cookie))

    def acquire_connection(self, auto_login=True, headers=None, rid=-1):
        '''Check out an available HTTPConnection instance.

        Blocks until a connection is available.
        :auto_login: automatically logins before returning conn
        :headers: header to pass on to login attempt
        :param rid: request id passed in from request eventlet.
        :returns: An available HTTPConnection instance or None if no
                 api_providers are configured.
        '''
        if not self._api_providers:
            LOG.warn(_LW("[%d] no API providers currently available."), rid)
            return None
        if self._conn_pool.empty():
            LOG.debug("[%d] Waiting to acquire API client connection.", rid)
        priority, conn = self._conn_pool.get()
        now = time.time()
        if getattr(conn, 'last_used', now) < now - cfg.CONF.conn_idle_timeout:
            LOG.info(_LI("[%(rid)d] Connection %(conn)s idle for %(sec)0.2f "
                         "seconds; reconnecting."),
                     {'rid': rid, 'conn': api_client.ctrl_conn_to_str(conn),
                      'sec': now - conn.last_used})
            conn = self._create_connection(*self._conn_params(conn))

        conn.last_used = now
        conn.priority = priority  # stash current priority for release
        qsize = self._conn_pool.qsize()
        LOG.debug("[%(rid)d] Acquired connection %(conn)s. %(qsize)d "
                  "connection(s) available.",
                  {'rid': rid, 'conn': api_client.ctrl_conn_to_str(conn),
                   'qsize': qsize})
        if auto_login and self.auth_cookie(conn) is None:
            self._wait_for_login(conn, headers)
        return conn

    def release_connection(self, http_conn, bad_state=False,
                           service_unavail=False, rid=-1):
        '''Mark HTTPConnection instance as available for check-out.

        :param http_conn: An HTTPConnection instance obtained from this
            instance.
        :param bad_state: True if http_conn is known to be in a bad state
                (e.g. connection fault.)
        :service_unavail: True if http_conn returned 503 response.
        :param rid: request id passed in from request eventlet.
        '''
        conn_params = self._conn_params(http_conn)
        if self._conn_params(http_conn) not in self._api_providers:
            LOG.debug("[%(rid)d] Released connection %(conn)s is not an "
                      "API provider for the cluster",
                      {'rid': rid,
                       'conn': api_client.ctrl_conn_to_str(http_conn)})
            return
        elif hasattr(http_conn, "no_release"):
            return

        priority = http_conn.priority
        if bad_state:
            # Reconnect to provider.
            LOG.warn(_LW("[%(rid)d] Connection returned in bad state, "
                         "reconnecting to %(conn)s"),
                     {'rid': rid,
                      'conn': api_client.ctrl_conn_to_str(http_conn)})
            http_conn = self._create_connection(*self._conn_params(http_conn))
        elif service_unavail:
            # http_conn returned a service unaviable response, put other
            # connections to the same controller at end of priority queue,
            conns = []
            while not self._conn_pool.empty():
                priority, conn = self._conn_pool.get()
                if self._conn_params(conn) == conn_params:
                    priority = self._next_conn_priority
                    self._next_conn_priority += 1
                conns.append((priority, conn))
            for priority, conn in conns:
                self._conn_pool.put((priority, conn))
            # put http_conn at end of queue also
            priority = self._next_conn_priority
            self._next_conn_priority += 1

        self._conn_pool.put((priority, http_conn))
        LOG.debug("[%(rid)d] Released connection %(conn)s. %(qsize)d "
                  "connection(s) available.",
                  {'rid': rid, 'conn': api_client.ctrl_conn_to_str(http_conn),
                   'qsize': self._conn_pool.qsize()})

    def _wait_for_login(self, conn, headers=None):
        '''Block until a login has occurred for the current API provider.'''

        data = self._get_provider_data(conn)
        if data is None:
            LOG.error(_LE("Login request for an invalid connection: '%s'"),
                      api_client.ctrl_conn_to_str(conn))
            return
        provider_sem = data[0]
        if provider_sem.acquire(blocking=False):
            try:
                cookie = self._login(conn, headers)
                self.set_auth_cookie(conn, cookie)
            finally:
                provider_sem.release()
        else:
            LOG.debug("Waiting for auth to complete")
            # Wait until we can acquire then release
            provider_sem.acquire(blocking=True)
            provider_sem.release()

    def _get_provider_data(self, conn_or_conn_params, default=None):
        """Get data for specified API provider.

        Args:
            conn_or_conn_params: either a HTTP(S)Connection object or the
                resolved conn_params tuple returned by self._conn_params().
            default: conn_params if ones passed aren't known
        Returns: Data associated with specified provider
        """
        conn_params = self._normalize_conn_params(conn_or_conn_params)
        return self._api_provider_data.get(conn_params, default)

    def _set_provider_data(self, conn_or_conn_params, data):
        """Set data for specified API provider.

        Args:
            conn_or_conn_params: either a HTTP(S)Connection object or the
                resolved conn_params tuple returned by self._conn_params().
            data: data to associate with API provider
        """
        conn_params = self._normalize_conn_params(conn_or_conn_params)
        if data is None:
            del self._api_provider_data[conn_params]
        else:
            self._api_provider_data[conn_params] = data

    def _normalize_conn_params(self, conn_or_conn_params):
        """Normalize conn_param tuple.

        Args:
            conn_or_conn_params: either a HTTP(S)Connection object or the
                resolved conn_params tuple returned by self._conn_params().

        Returns: Normalized conn_param tuple
        """
        if (not isinstance(conn_or_conn_params, tuple) and
            not isinstance(conn_or_conn_params, httplib.HTTPConnection)):
            LOG.debug("Invalid conn_params value: '%s'",
                      str(conn_or_conn_params))
            return conn_or_conn_params
        if isinstance(conn_or_conn_params, httplib.HTTPConnection):
            conn_params = self._conn_params(conn_or_conn_params)
        else:
            conn_params = conn_or_conn_params
        host, port, is_ssl = conn_params
        if port is None:
            port = 443 if is_ssl else 80
        return (host, port, is_ssl)
