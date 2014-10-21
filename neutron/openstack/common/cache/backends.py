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

import abc

import six


NOTSET = object()


@six.add_metaclass(abc.ABCMeta)
class BaseCache(object):
    """Base Cache Abstraction

    :params parsed_url: Parsed url object.
    :params options: A dictionary with configuration parameters
      for the cache. For example:

        - default_ttl: An integer defining the default ttl for keys.
    """

    def __init__(self, parsed_url, options=None):
        self._parsed_url = parsed_url
        self._options = options or {}
        self._default_ttl = int(self._options.get('default_ttl', 0))

    @abc.abstractmethod
    def _set(self, key, value, ttl, not_exists=False):
        """Implementations of this class have to override this method."""

    def set(self, key, value, ttl, not_exists=False):
        """Sets or updates a cache entry

        .. note:: Thread-safety is required and has to be guaranteed by the
           backend implementation.

        :params key: Item key as string.
        :type key: `unicode string`
        :params value: Value to assign to the key. This can be anything that
          is handled by the current backend.
        :params ttl: Key's timeout in seconds. 0 means no timeout.
        :type ttl: int
        :params not_exists: If True, the key will be set if it doesn't exist.
          Otherwise, it'll always be set.
        :type not_exists: bool

        :returns: True if the operation succeeds, False otherwise.
        """
        if ttl is None:
            ttl = self._default_ttl

        return self._set(key, value, ttl, not_exists)

    def __setitem__(self, key, value):
        self.set(key, value, self._default_ttl)

    def setdefault(self, key, value):
        """Sets the key value to `value` if it doesn't exist

        :params key: Item key as string.
        :type key: `unicode string`
        :params value: Value to assign to the key. This can be anything that
          is handled by the current backend.
        """
        try:
            return self[key]
        except KeyError:
            self[key] = value
            return value

    @abc.abstractmethod
    def _get(self, key, default):
        """Implementations of this class have to override this method."""

    def get(self, key, default=None):
        """Gets one item from the cache

        .. note:: Thread-safety is required and it has to be guaranteed
           by the backend implementation.

        :params key: Key for the item to retrieve from the cache.
        :params default: The default value to return.

        :returns: `key`'s value in the cache if it exists, otherwise
          `default` should be returned.
        """
        return self._get(key, default)

    def __getitem__(self, key):
        value = self.get(key, NOTSET)

        if value is NOTSET:
            raise KeyError

        return value

    @abc.abstractmethod
    def __delitem__(self, key):
        """Removes an item from cache.

        .. note:: Thread-safety is required and it has to be guaranteed by
           the backend implementation.

        :params key: The key to remove.

        :returns: The key value if there's one
        """

    @abc.abstractmethod
    def _clear(self):
        """Implementations of this class have to override this method."""

    def clear(self):
        """Removes all items from the cache.

        .. note:: Thread-safety is required and it has to be guaranteed by
           the backend implementation.
        """
        return self._clear()

    @abc.abstractmethod
    def _incr(self, key, delta):
        """Implementations of this class have to override this method."""

    def incr(self, key, delta=1):
        """Increments the value for a key

        :params key: The key for the value to be incremented
        :params delta: Number of units by which to increment the value.
          Pass a negative number to decrement the value.

        :returns: The new value
        """
        return self._incr(key, delta)

    @abc.abstractmethod
    def _append_tail(self, key, tail):
        """Implementations of this class have to override this method."""

    def append_tail(self, key, tail):
        """Appends `tail` to `key`'s value.

        :params key: The key of the value to which `tail` should be appended.
        :params tail: The list of values to append to the original.

        :returns: The new value
        """

        if not hasattr(tail, "__iter__"):
            raise TypeError('Tail must be an iterable')

        if not isinstance(tail, list):
            # NOTE(flaper87): Make sure we pass a list
            # down to the implementation. Not all drivers
            # have support for generators, sets or other
            # iterables.
            tail = list(tail)

        return self._append_tail(key, tail)

    def append(self, key, value):
        """Appends `value` to `key`'s value.

        :params key: The key of the value to which `tail` should be appended.
        :params value: The value to append to the original.

        :returns: The new value
        """
        return self.append_tail(key, [value])

    @abc.abstractmethod
    def __contains__(self, key):
        """Verifies that a key exists.

        :params key: The key to verify.

        :returns: True if the key exists, otherwise False.
        """

    @abc.abstractmethod
    def _get_many(self, keys, default):
        """Implementations of this class have to override this method."""
        return ((k, self.get(k, default=default)) for k in keys)

    def get_many(self, keys, default=NOTSET):
        """Gets keys' value from cache

        :params keys: List of keys to retrieve.
        :params default: The default value to return for each key that is not
          in the cache.

        :returns: A  generator of (key, value)
        """
        return self._get_many(keys, default)

    @abc.abstractmethod
    def _set_many(self, data, ttl):
        """Implementations of this class have to override this method."""

        for key, value in data.items():
            self.set(key, value, ttl=ttl)

    def set_many(self, data, ttl=None):
        """Puts several items into the cache at once

        Depending on the backend, this operation may or may not be efficient.
        The default implementation calls set for each (key, value) pair
        passed, other backends support set_many operations as part of their
        protocols.

        :params data: A dictionary like {key: val} to store in the cache.
        :params ttl: Key's timeout in seconds.
        """

        if ttl is None:
            ttl = self._default_ttl

        self._set_many(data, ttl)

    def update(self, **kwargs):
        """Sets several (key, value) paris.

        Refer to the `set_many` docstring.
        """
        self.set_many(kwargs, ttl=self._default_ttl)

    @abc.abstractmethod
    def _unset_many(self, keys):
        """Implementations of this class have to override this method."""
        for key in keys:
            del self[key]

    def unset_many(self, keys):
        """Removes several keys from the cache at once

        :params keys: List of keys to unset.
        """
        self._unset_many(keys)
