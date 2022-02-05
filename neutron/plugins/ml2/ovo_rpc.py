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

import atexit
import queue
import signal
import threading
import traceback
import weakref

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import context as n_ctx
from neutron_lib.db import api as db_api
from oslo_log import log as logging

from neutron.api.rpc.callbacks import events as rpc_events
from neutron.api.rpc.handlers import resources_rpc
from neutron.common import utils
from neutron.objects import address_group
from neutron.objects import network
from neutron.objects import ports
from neutron.objects import securitygroup
from neutron.objects import subnet

LOG = logging.getLogger(__name__)


def _setup_change_handlers_cleanup():
    atexit.register(_ObjectChangeHandler.clean_up)
    signal.signal(signal.SIGINT, _ObjectChangeHandler.clean_up)
    signal.signal(signal.SIGTERM, _ObjectChangeHandler.clean_up)


class _ObjectChangeHandler(object):
    MAX_IDLE_FOR = 1
    _TO_CLEAN = weakref.WeakSet()

    def __init__(self, resource, object_class, resource_push_api):
        self._resource = resource
        self._obj_class = object_class
        self._resource_push_api = resource_push_api
        self._resources_to_push = queue.Queue()
        self._semantic_warned = False
        for event in (events.AFTER_CREATE, events.AFTER_UPDATE,
                      events.AFTER_DELETE):
            registry.subscribe(self.handle_event, resource, event)

        self._stop = threading.Event()
        self._worker = threading.Thread(
            target=self.dispatch_events,
            name='ObjectChangeHandler[%s]' % self._resource,
            daemon=True)
        self._worker.start()
        self._TO_CLEAN.add(self)

    def stop(self):
        self._stop.set()

    def wait(self):
        """Waits for all outstanding events to be dispatched."""
        self._resources_to_push.join()

    def _is_session_semantic_violated(self, context, resource, event):
        """Return True and print an ugly error on transaction violation.

        This code is to print ugly errors when AFTER_CREATE/UPDATE
        event transaction semantics are violated by other parts of
        the code.
        """
        if not utils.is_session_active(context.session):
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

    def handle_event(self, resource, event, trigger, payload):
        """Callback handler for resource change that pushes change to RPC.

        We always retrieve the latest state and ignore what was in the
        payload to ensure that we don't get any stale data.
        """
        if self._is_session_semantic_violated(
                payload.context, resource, event):
            return
        resource_id = payload.resource_id
        # we preserve the context so we can trace a receive on the agent back
        # to the server-side event that triggered it
        self._resources_to_push.put((resource_id, payload.context.to_dict()))

    def dispatch_events(self):
        # TODO(kevinbenton): now that we are batching these, convert to a
        # single get_objects call for all of them
        LOG.debug('Thread %(name)s started', {'name': self._worker.name})
        while not self._stop.is_set():
            try:
                resource_id, context_dict = self._resources_to_push.get(
                    timeout=self.MAX_IDLE_FOR)
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
                self._resources_to_push.task_done()
            except queue.Empty:
                pass
            except Exception as e:
                LOG.exception(
                    "Exception while dispatching %(res)s events: %(e)s",
                    {'res': self._resource, 'e': e})
        LOG.debug('Thread %(name)s finished with %(msgs)s unsent messages',
                  {'name': self._worker.name,
                   'msgs': self._resources_to_push.unfinished_tasks})

    @classmethod
    def clean_up(cls, *args, **kwargs):
        """Ensure all threads that were created were destroyed cleanly."""
        while cls._TO_CLEAN:
            worker = cls._TO_CLEAN.pop()
            worker.stop()


class OVOServerRpcInterface(object):
    """ML2 server-side RPC interface.

    Generates RPC callback notifications on ML2 object changes.
    """

    def __init__(self):
        self._rpc_pusher = resources_rpc.ResourcesPushRpcApi()
        self._setup_change_handlers()
        _setup_change_handlers_cleanup()
        LOG.debug("ML2 OVO RPC backend initialized.")

    def _setup_change_handlers(self):
        """Setup all of the local callback listeners for resource changes."""
        resource_objclass_map = {
            resources.PORT: ports.Port,
            resources.SUBNET: subnet.Subnet,
            resources.NETWORK: network.Network,
            resources.SECURITY_GROUP: securitygroup.SecurityGroup,
            resources.SECURITY_GROUP_RULE: securitygroup.SecurityGroupRule,
            resources.ADDRESS_GROUP: address_group.AddressGroup,
        }
        self._resource_handlers = {
            res: _ObjectChangeHandler(res, obj_class, self._rpc_pusher)
            for res, obj_class in resource_objclass_map.items()
        }

    def wait(self):
        """Wait for all handlers to finish processing async events."""
        for handler in self._resource_handlers.values():
            handler.wait()
