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

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib import context as n_ctx
from neutron_lib import rpc as n_rpc
from oslo_log import log as logging

from neutron._i18n import _
from neutron.api.rpc.callbacks.consumer import registry as registry_rpc
from neutron.api.rpc.callbacks import events as events_rpc
from neutron.api.rpc.handlers import resources_rpc
from neutron import objects

LOG = logging.getLogger(__name__)
objects.register_objects()


class RemoteResourceCache(object):
    """Retrieves and stashes logical resources in their OVO format.

    This is currently only compatible with OVO objects that have an ID.
    """
    def __init__(self, resource_types):
        self.resource_types = resource_types
        self._cache_by_type_and_id = {rt: {} for rt in self.resource_types}
        self._deleted_ids_by_type = {rt: set() for rt in self.resource_types}
        # track everything we've asked the server so we don't ask again
        self._satisfied_server_queries = set()
        self._puller = resources_rpc.ResourcesPullRpcApi()

    def _type_cache(self, rtype):
        if rtype not in self.resource_types:
            raise RuntimeError(_("Resource cache not tracking %s") % rtype)
        return self._cache_by_type_and_id[rtype]

    def start_watcher(self):
        self._watcher = RemoteResourceWatcher(self)

    def stop_watcher(self):
        self._watcher.stop()

    def get_resource_by_id(self, rtype, obj_id, agent_restarted=False):
        """Returns None if it doesn't exist."""
        if obj_id in self._deleted_ids_by_type[rtype]:
            return None
        cached_item = self._type_cache(rtype).get(obj_id)
        if cached_item:
            return cached_item
        # try server in case object existed before agent start
        self._flood_cache_for_query(rtype, id=(obj_id, ),
                                    agent_restarted=agent_restarted)
        return self._type_cache(rtype).get(obj_id)

    def _flood_cache_for_query(self, rtype, agent_restarted=False,
                               **filter_kwargs):
        """Load info from server for first query.

        Queries the server if this is the first time a given query for
        rtype has been issued.
        """
        query_ids = self._get_query_ids(rtype, filter_kwargs)
        if query_ids.issubset(self._satisfied_server_queries):
            # we've already asked the server this question so we don't
            # ask directly again because any updates will have been
            # pushed to us
            return
        context = n_ctx.get_admin_context()
        resources = self._puller.bulk_pull(context, rtype,
                                           filter_kwargs=filter_kwargs)
        for resource in resources:
            if self._is_stale(rtype, resource):
                # if the server was slow enough to respond the object may have
                # been updated already and pushed to us in another thread.
                LOG.debug("Ignoring stale update for %s: %s", rtype, resource)
                continue
            self.record_resource_update(context, rtype, resource,
                                        agent_restarted=agent_restarted)
        LOG.debug("%s resources returned for queries %s", len(resources),
                  query_ids)
        self._satisfied_server_queries.update(query_ids)

    def _get_query_ids(self, rtype, filters):
        """Turns filters for a given rypte into a set of query IDs.

        This can result in multiple queries due to the nature of the query
        processing on the server side. Since multiple values are treated as
        an OR condition, a query for {'id': ('1', '2')} is equivalent
        to a query for {'id': ('1',)} and {'id': ('2')}. This method splits
        the former into the latter to ensure we aren't asking the server
        something we already know.
        """
        query_ids = set()
        for k, values in tuple(sorted(filters.items())):
            if len(values) > 1:
                for v in values:
                    new_filters = filters.copy()
                    new_filters[k] = (v, )
                    query_ids.update(self._get_query_ids(rtype, new_filters))
                break
        else:
            # no multiple value filters left so add an ID
            query_ids.add((rtype, ) + tuple(sorted(filters.items())))
        return query_ids

    def get_resources(self, rtype, filters):
        """Find resources that match key:values in filters dict.

        If the attribute on the object is a list, each value is checked if it
        is in the list.

        The values in the dictionary for a single key are matched in an OR
        fashion.
        """
        self._flood_cache_for_query(rtype, **filters)

        def match(obj):
            for key, values in filters.items():
                for value in values:
                    attr = getattr(obj, key)
                    if isinstance(attr, (list, tuple, set)):
                        # attribute is a list so we check if value is in
                        # list
                        if value in attr:
                            break
                    elif value == attr:
                        break
                else:
                    # no match found for this key
                    return False
            return True
        return self.match_resources_with_func(rtype, match)

    def match_resources_with_func(self, rtype, matcher):
        """Returns a list of all resources satisfying func matcher."""
        # TODO(kevinbenton): this is O(N), offer better lookup functions
        return [r for r in self._type_cache(rtype).values()
                if matcher(r)]

    def _is_stale(self, rtype, resource):
        """Determines if a given resource update is safe to ignore.

        It can be safe to ignore if it has already been deleted or if
        we have a copy with a higher revision number.
        """
        if resource.id in self._deleted_ids_by_type[rtype]:
            return True
        existing = self._type_cache(rtype).get(resource.id)
        if existing and existing.revision_number > resource.revision_number:
            # NOTE(kevinbenton): we could be strict and check for >=, but this
            # makes us more tolerant of bugs on the server where we forget to
            # bump the revision_number.
            return True
        return False

    def record_resource_update(self, context, rtype, resource,
                               agent_restarted=False):
        """Takes in an OVO and generates an event on relevant changes.

        A change is deemed to be relevant if it is not stale and if any
        fields changed beyond the revision number and update time.

        Both creates and updates are handled in this function.
        """
        if self._is_stale(rtype, resource):
            LOG.debug("Ignoring stale update for %s: %s", rtype, resource)
            return
        existing = self._type_cache(rtype).get(resource.id)
        self._type_cache(rtype)[resource.id] = resource
        changed_fields = self._get_changed_fields(existing, resource)
        if not changed_fields:
            LOG.debug("Received resource %s update without any changes: %s",
                      rtype, resource.id)
            return
        if existing:
            LOG.debug("Resource %s %s updated (revision_number %s->%s). "
                      "Old fields: %s New fields: %s",
                      rtype, existing.id, existing.revision_number,
                      resource.revision_number,
                      {f: existing.get(f) for f in changed_fields},
                      {f: resource.get(f) for f in changed_fields})
        else:
            LOG.debug("Received new resource %s: %s", rtype, resource)
        # local notification for agent internals to subscribe to
        registry.publish(rtype, events.AFTER_UPDATE, self,
                         payload=events.DBEventPayload(
                             context,
                             metadata={'changed_fields': changed_fields,
                                       'agent_restarted': agent_restarted},
                             resource_id=resource.id,
                             states=(existing, resource)))

    def record_resource_delete(self, context, rtype, resource_id):
        # deletions are final, record them so we never
        # accept new data for the same ID.
        LOG.debug("Resource %s deleted: %s", rtype, resource_id)
        # TODO(kevinbenton): we need a way to expire items from the set at
        # some TTL so it doesn't grow indefinitely with churn
        if resource_id in self._deleted_ids_by_type[rtype]:
            LOG.debug("Skipped duplicate delete event for %s", resource_id)
            return
        self._deleted_ids_by_type[rtype].add(resource_id)
        existing = self._type_cache(rtype).pop(resource_id, None)
        # local notification for agent internals to subscribe to
        registry.publish(rtype, events.AFTER_DELETE, self,
                         payload=events.DBEventPayload(
                             context,
                             resource_id=resource_id,
                             states=(existing,)))

    def _get_changed_fields(self, old, new):
        """Returns changed fields excluding update time and revision."""
        new = new.to_dict()
        changed = set(new)
        if old:
            for k, v in old.to_dict().items():
                if v == new.get(k):
                    changed.discard(k)
        for ignore in ('revision_number', 'updated_at'):
            changed.discard(ignore)
        return changed


class RemoteResourceWatcher(object):
    """Converts RPC callback notifications to local registry notifications.

    This allows a constructor to listen for RPC callbacks for a given
    dictionary of resources and fields desired.
    This watcher will listen to the RPC callbacks as sent on the wire and
    handle things like out-of-order message detection and throwing away
    updates to fields the constructor doesn't care about.

    All watched resources must be primary keyed on a field called 'id' and
    have a standard attr revision number.
    """

    def __init__(self, remote_resource_cache):
        self.rcache = remote_resource_cache
        self._init_rpc_listeners()

    def _init_rpc_listeners(self):
        endpoints = [resources_rpc.ResourcesPushRpcCallback()]
        self._connection = n_rpc.Connection()
        for rtype in self.rcache.resource_types:
            registry_rpc.register(self.resource_change_handler, rtype)
            topic = resources_rpc.resource_type_versioned_topic(rtype)
            self._connection.create_consumer(topic, endpoints, fanout=True)
        self._connection.consume_in_threads()

    def resource_change_handler(self, context, rtype, resources, event_type):
        for r in resources:
            if event_type == events_rpc.DELETED:
                self.rcache.record_resource_delete(context, rtype, r.id)
            else:
                # creates and updates are treated equally
                self.rcache.record_resource_update(context, rtype, r)

    def stop(self):
        self._connection.close()
