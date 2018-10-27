#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import traceback

import futurist
from futurist import waiters

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import context as n_ctx
from neutron_lib.db import api as db_api
from oslo_concurrency import lockutils
from oslo_log import log as logging

from neutron._i18n import _
from neutron.api.rpc.callbacks import events as rpc_events
from neutron.api.rpc.handlers import resources_rpc
from neutron.objects import network
from neutron.objects import ports
from neutron.objects import securitygroup
from neutron.objects import subnet

LOG = logging.getLogger(__name__)


class _ObjectChangeHandler(object):
    def __init__(self, resource, object_class, resource_push_api):
        self._resource = resource
        self._obj_class = object_class
        self._resource_push_api = resource_push_api
        self._resources_to_push = {}

        # NOTE(annp): uWSGI seems not happy with eventlet.GreenPool.
        # So switching to ThreadPool
        self._worker_pool = futurist.ThreadPoolExecutor()
        self.fts = []

        self._semantic_warned = False
        for event in (events.AFTER_CREATE, events.AFTER_UPDATE,
                      events.AFTER_DELETE):
            registry.subscribe(self.handle_event, resource, event)

    def wait(self):
        """Waits for all outstanding events to be dispatched."""
        done, not_done = waiters.wait_for_all(self.fts)
        if not not_done:
            del self.fts[:]

    def _is_session_semantic_violated(self, context, resource, event):
        """Return True and print an ugly error on transaction violation.

        This code is to print ugly errors when AFTER_CREATE/UPDATE
        event transaction semantics are violated by other parts of
        the code.
        """
        if not context.session.is_active:
            return False
        if not self._semantic_warned:
            stack = traceback.extract_stack()
            stack = "".join(traceback.format_list(stack))
            LOG.warning("This handler is supposed to handle AFTER "
                        "events, as in 'AFTER it's committed', "
                        "not BEFORE. Offending resource event: "
                        "%(r)s, %(e)s. Location:\n%(l)s",
                        {'r': resource, 'e': event, 'l': stack})
            self._semantic_warned = True
        return True

    def handle_event(self, resource, event, trigger,
                     context, *args, **kwargs):
        """Callback handler for resource change that pushes change to RPC.

        We always retrieve the latest state and ignore what was in the
        payload to ensure that we don't get any stale data.
        """
        if self._is_session_semantic_violated(context, resource, event):
            return
        resource_id = self._extract_resource_id(kwargs)
        # we preserve the context so we can trace a receive on the agent back
        # to the server-side event that triggered it
        self._resources_to_push[resource_id] = context.to_dict()
        # spawn worker so we don't block main AFTER_UPDATE thread
        self.fts.append(self._worker_pool.submit(self.dispatch_events))

    @lockutils.synchronized('event-dispatch')
    def dispatch_events(self):
        # this is guarded by a lock to ensure we don't get too many concurrent
        # dispatchers hitting the database simultaneously.
        to_dispatch, self._resources_to_push = self._resources_to_push, {}
        # TODO(kevinbenton): now that we are batching these, convert to a
        # single get_objects call for all of them
        for resource_id, context_dict in to_dispatch.items():
            context = n_ctx.Context.from_dict(context_dict)
            # attempt to get regardless of event type so concurrent delete
            # after create/update is the same code-path as a delete event
            with db_api.get_context_manager().independent.reader.using(
                    context):
                obj = self._obj_class.get_object(context, id=resource_id)
            # CREATE events are always treated as UPDATE events to ensure
            # listeners are written to handle out-of-order messages
            if obj is None:
                rpc_event = rpc_events.DELETED
                # construct a fake object with the right ID so we can
                # have a payload for the delete message.
                obj = self._obj_class(id=resource_id)
            else:
                rpc_event = rpc_events.UPDATED
            self._resource_push_api.push(context, [obj], rpc_event)

    def _extract_resource_id(self, callback_kwargs):
        id_kwarg = '%s_id' % self._resource
        if id_kwarg in callback_kwargs:
            return callback_kwargs[id_kwarg]
        if self._resource in callback_kwargs:
            return callback_kwargs[self._resource]['id']
        raise RuntimeError(_("Couldn't find resource ID in callback event"))


class OVOServerRpcInterface(object):
    """ML2 server-side RPC interface.

    Generates RPC callback notifications on ML2 object changes.
    """

    def __init__(self):
        self._rpc_pusher = resources_rpc.ResourcesPushRpcApi()
        self._setup_change_handlers()
        LOG.debug("ML2 OVO RPC backend initialized.")

    def _setup_change_handlers(self):
        """Setup all of the local callback listeners for resource changes."""
        resource_objclass_map = {
            resources.PORT: ports.Port,
            resources.SUBNET: subnet.Subnet,
            resources.NETWORK: network.Network,
            resources.SECURITY_GROUP: securitygroup.SecurityGroup,
            resources.SECURITY_GROUP_RULE: securitygroup.SecurityGroupRule,
        }
        self._resource_handlers = {
            res: _ObjectChangeHandler(res, obj_class, self._rpc_pusher)
            for res, obj_class in resource_objclass_map.items()
        }

    def wait(self):
        """Wait for all handlers to finish processing async events."""
        for handler in self._resource_handlers.values():
            handler.wait()
