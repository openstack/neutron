# Copyright 2019 Red Hat, Inc.
# All Rights Reserved.
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

import datetime

from oslo_log import log
from oslo_utils import timeutils
import six
from tooz import hashring

from neutron.common.ovn import constants
from neutron.common.ovn import exceptions
from neutron.db import ovn_hash_ring_db as db_hash_ring
from neutron_lib import context

LOG = log.getLogger(__name__)


class HashRingManager(object):

    def __init__(self, group_name):
        self._hash_ring = None
        self._last_time_loaded = None
        self._cache_startup_timeout = True
        self._group = group_name
        self.admin_ctx = context.get_admin_context()

    @property
    def _wait_startup_before_caching(self):
        # NOTE(lucasagomes): Some events are processed at the service's
        # startup time and since many services may be started concurrently
        # we do not want to use a cached hash ring at that point. This
        # method checks if the created_at and updated_at columns from the
        # nodes in the ring from this host is equal, and if so it means
        # that the service just started.

        # If the startup timeout already expired, there's no reason to
        # keep reading from the DB. At this point this will always
        # return False
        if not self._cache_startup_timeout:
            return False

        nodes = db_hash_ring.get_active_nodes(
            self.admin_ctx,
            constants.HASH_RING_CACHE_TIMEOUT, self._group, from_host=True)
        dont_cache = nodes and nodes[0].created_at == nodes[0].updated_at
        if not dont_cache:
            self._cache_startup_timeout = False

        return dont_cache

    def _load_hash_ring(self, refresh=False):
        cache_timeout = timeutils.utcnow() - datetime.timedelta(
            seconds=constants.HASH_RING_CACHE_TIMEOUT)

        # Refresh the cache if:
        # - Refreshed is forced (refresh=True)
        # - Service just started (_wait_startup_before_caching)
        # - Hash Ring is not yet instantiated
        # - Cache has timed out
        if (refresh or
                self._wait_startup_before_caching or
                self._hash_ring is None or
                not self._hash_ring.nodes or
                cache_timeout >= self._last_time_loaded):
            nodes = db_hash_ring.get_active_nodes(
                self.admin_ctx,
                constants.HASH_RING_NODES_TIMEOUT, self._group)
            self._hash_ring = hashring.HashRing({node.node_uuid
                                                 for node in nodes})
            self._last_time_loaded = timeutils.utcnow()

    def refresh(self):
        self._load_hash_ring(refresh=True)

    def get_node(self, key):
        self._load_hash_ring()

        # tooz expects a byte string for the hash
        if isinstance(key, six.string_types):
            key = key.encode('utf-8')

        try:
            # We need to pop the value from the set. If empty,
            # KeyError is raised
            return self._hash_ring[key].pop()
        except KeyError:
            raise exceptions.HashRingIsEmpty(key=key)
