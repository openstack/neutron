# Copyright 2013 Red Hat, Inc.
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

import collections

from oslo.utils import timeutils
from oslo_concurrency import lockutils

from neutron.openstack.common.cache import backends


class MemoryBackend(backends.BaseCache):

    def __init__(self, parsed_url, options=None):
        super(MemoryBackend, self).__init__(parsed_url, options)
        self._clear()

    def _set_unlocked(self, key, value, ttl=0):
        expires_at = 0
        if ttl != 0:
            expires_at = timeutils.utcnow_ts() + ttl

        self._cache[key] = (expires_at, value)

        if expires_at:
            self._keys_expires[expires_at].add(key)

    def _set(self, key, value, ttl=0, not_exists=False):
        with lockutils.lock(key):

            # NOTE(flaper87): This is needed just in `set`
            # calls, hence it's not in `_set_unlocked`
            if not_exists and self._exists_unlocked(key):
                return False

            self._set_unlocked(key, value, ttl)
            return True

    def _get_unlocked(self, key, default=None):
        now = timeutils.utcnow_ts()

        try:
            timeout, value = self._cache[key]
        except KeyError:
            return (0, default)

        if timeout and now >= timeout:

            # NOTE(flaper87): Record expired,
            # remove it from the cache but catch
            # KeyError and ValueError in case
            # _purge_expired removed this key already.
            try:
                del self._cache[key]
            except KeyError:
                pass

            try:
                # NOTE(flaper87): Keys with ttl == 0
                # don't exist in the _keys_expires dict
                self._keys_expires[timeout].remove(key)
            except (KeyError, ValueError):
                pass

            return (0, default)

        return (timeout, value)

    def _get(self, key, default=None):
        with lockutils.lock(key):
            return self._get_unlocked(key, default)[1]

    def _exists_unlocked(self, key):
        now = timeutils.utcnow_ts()
        try:
            timeout = self._cache[key][0]
            return not timeout or now <= timeout
        except KeyError:
            return False

    def __contains__(self, key):
        with lockutils.lock(key):
            return self._exists_unlocked(key)

    def _incr_append(self, key, other):
        with lockutils.lock(key):
            timeout, value = self._get_unlocked(key)

            if value is None:
                return None

            ttl = timeutils.utcnow_ts() - timeout
            new_value = value + other
            self._set_unlocked(key, new_value, ttl)
            return new_value

    def _incr(self, key, delta):
        if not isinstance(delta, int):
            raise TypeError('delta must be an int instance')

        return self._incr_append(key, delta)

    def _append_tail(self, key, tail):
        return self._incr_append(key, tail)

    def _purge_expired(self):
        """Removes expired keys from the cache."""

        now = timeutils.utcnow_ts()
        for timeout in sorted(self._keys_expires.keys()):

            # NOTE(flaper87): If timeout is greater
            # than `now`, stop the iteration, remaining
            # keys have not expired.
            if now < timeout:
                break

            # NOTE(flaper87): Unset every key in
            # this set from the cache if its timeout
            # is equal to `timeout`. (The key might
            # have been updated)
            for subkey in self._keys_expires.pop(timeout):
                try:
                    if self._cache[subkey][0] == timeout:
                        del self._cache[subkey]
                except KeyError:
                    continue

    def __delitem__(self, key):
        self._purge_expired()

        # NOTE(flaper87): Delete the key. Using pop
        # since it could have been deleted already
        value = self._cache.pop(key, None)

        if value:
            try:
                # NOTE(flaper87): Keys with ttl == 0
                # don't exist in the _keys_expires dict
                self._keys_expires[value[0]].remove(key)
            except (KeyError, ValueError):
                pass

    def _clear(self):
        self._cache = {}
        self._keys_expires = collections.defaultdict(set)

    def _get_many(self, keys, default):
        return super(MemoryBackend, self)._get_many(keys, default)

    def _set_many(self, data, ttl=0):
        return super(MemoryBackend, self)._set_many(data, ttl)

    def _unset_many(self, keys):
        return super(MemoryBackend, self)._unset_many(keys)
