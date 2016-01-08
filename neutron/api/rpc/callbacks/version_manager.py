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
import copy
import time

from oslo_log import log as logging

from neutron.api.rpc.callbacks import resources

LOG = logging.getLogger(__name__)

VERSIONS_TTL = 60


class ResourceConsumerTracker(object):
    """Class to be provided back by consumer_versions_callback.

    This class is responsible for fetching the local versions of
    resources, and letting the callback register every consumer's
    resource version.

    Later on, this class can also be used to recalculate, for each
    resource type, the collection of versions that are local or
    known by one or more consumers.
    """

    def __init__(self):
        # Initialize with the local (server) versions, as we always want
        # to send those. Agents, as they upgrade, will need the latest version,
        # and there is a corner case we'd not be covering otherwise:
        #   1) one or several neutron-servers get disconnected from rpc (while
        #      running)
        #   2) a new agent comes up, with the latest version and it reports
        #      2 ways:
        #     a) via status report (which will be stored in the database)
        #     b) via fanout call to all neutron servers, this way, all of them
        #        get their version set updated right away without the need to
        #        re-fetch anything from the database.
        #   3) the neutron-servers get back online to the rpc bus, but they
        #      lost the fanout message.
        #
        # TODO(mangelajo) To cover this case we may need a callback from oslo
        # messaging to get notified about disconnections/reconnections to the
        # rpc bus, invalidating the consumer version cache when we receive such
        # callback.
        self._versions = self._get_local_resource_versions()
        self._versions_by_consumer = collections.defaultdict(dict)
        self._needs_recalculation = False

    def _get_local_resource_versions(self):
        local_resource_versions = collections.defaultdict(set)
        for resource_type, version in (
                resources.LOCAL_RESOURCE_VERSIONS.items()):
            local_resource_versions[resource_type].add(version)
        return local_resource_versions

    # TODO(mangelajo): add locking with _recalculate_versions if we ever
    #                  move out of green threads.
    def _set_version(self, consumer_id, resource_type, version):
        """Set or update a consumer resource type version."""
        self._versions[resource_type].add(version)
        prev_version = (
            self._versions_by_consumer[consumer_id].get(resource_type, None))
        self._versions_by_consumer[consumer_id][resource_type] = version
        if prev_version and (prev_version != version):
            # If a version got updated/changed in a consumer, we need to
            # recalculate the main dictionary of versions based on the
            # new _versions_by_consumer.
            # We defer the recalculation until every consumer version has
            # been set for all of its resource types.
            self._needs_recalculation = True
            LOG.debug("Version for resource type %(resource_type)s changed "
                      "%(prev_version)s to %(version)s on "
                      "consumer %(consumer_id)s",
                      {'resource_type': resource_type,
                       'version': version,
                       'prev_version': prev_version,
                       'consumer_id': consumer_id})

    def set_versions(self, consumer_id, versions):
        """Set or update an specific consumer resource types."""
        for resource_type, resource_version in versions.items():
            self._set_version(consumer_id, resource_type,
                             resource_version)

    def get_resource_versions(self, resource_type):
        """Fetch the versions necessary to notify all consumers."""
        if self._needs_recalculation:
            self._recalculate_versions()
            self._needs_recalculation = False

        return copy.copy(self._versions[resource_type])

    # TODO(mangelajo): Add locking if we ever move out of greenthreads.
    def _recalculate_versions(self):
        """Recalculate the _versions set.

        Re-fetch the local (server) versions and expand with consumers'
        versions.
        """
        versions = self._get_local_resource_versions()
        for versions_dict in self._versions_by_consumer.values():
            for res_type, res_version in versions_dict.items():
                versions[res_type].add(res_version)
        self._versions = versions


class CachedResourceConsumerTracker(object):
    """This class takes care of the caching logic of versions."""

    def __init__(self):
        self._consumer_versions_callback = None
        # This is TTL expiration time, 0 means it will be expired at start
        self._expires_at = 0
        self._versions = ResourceConsumerTracker()

    def _update_consumer_versions(self):
        if self._consumer_versions_callback:
            new_tracker = ResourceConsumerTracker()
            self._consumer_versions_callback(new_tracker)
            self._versions = new_tracker
        else:
            pass  # TODO(mangelajo): throw exception if callback not provided

    def _check_expiration(self):
        if time.time() > self._expires_at:
            self._update_consumer_versions()
            self._expires_at = time.time() + VERSIONS_TTL

    def set_consumer_versions_callback(self, callback):
        self._consumer_versions_callback = callback

    def get_resource_versions(self, resource_type):
        self._check_expiration()
        return self._versions.get_resource_versions(resource_type)

    def update_versions(self, consumer_id, resource_versions):
        self._versions.set_versions(consumer_id, resource_versions)


cached_version_tracker = CachedResourceConsumerTracker()


def set_consumer_versions_callback(callback):
    """Register a callback to retrieve the system consumer versions.

    Specific consumer logic has been decoupled from this, so we could reuse
    in other places.

    The callback will receive a ResourceConsumerTracker object,
    and the ResourceConsumerTracker methods must be used to provide
    each consumer_id versions. Consumer ids can be obtained from this
    module via the next functions:
        * get_agent_consumer_id
    """
    cached_version_tracker.set_consumer_versions_callback(callback)


def get_resource_versions(resource_type):
    """Return the set of versions expected by the consumers of a resource."""
    return cached_version_tracker.get_resource_versions(resource_type)


def update_versions(consumer_id, resource_versions):
    """Update the resources' versions for a consumer id."""
    cached_version_tracker.set_versions(consumer_id, resource_versions)


def get_agent_consumer_id(agent_type, agent_host):
    """Return a consumer id string for an agent type + host tuple.

    The logic behind this function, is that, eventually we could have
    consumers of RPC callbacks which are not agents, thus we want
    to totally collate all the different consumer types and provide
    unique consumer ids.
    """
    return "%(agent_type)s@%(agent_host)s" % {'agent_type': agent_type,
                                              'agent_host': agent_host}
