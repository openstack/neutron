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

from oslo_log import log as logging

from neutron._i18n import _LE
from neutron.api.rpc.callbacks import events as rpc_events
from neutron.api.rpc.handlers import resources_rpc
from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.db import api as db_api
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
        for event in (events.AFTER_CREATE, events.AFTER_UPDATE,
                      events.AFTER_DELETE):
            registry.subscribe(self.handle_event, resource, event)

    @staticmethod
    def _is_session_semantic_violated(context, resource, event):
        """Return True and print an ugly error on transaction violation.

        This code is to print ugly errors when AFTER_CREATE/UPDATE
        event transaction semantics are violated by other parts of
        the code.
        """
        if not context.session.is_active:
            return False
        stack = traceback.extract_stack()
        stack = "".join(traceback.format_list(stack))
        LOG.error(_LE("This handler is supposed to handle AFTER "
                      "events, as in 'AFTER it's committed', "
                      "not BEFORE. Offending resource event: "
                      "%(r)s, %(e)s. Location:\n%(l)s"),
                  {'r': resource, 'e': event, 'l': stack})
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
        # attempt to get regardless of event type so concurrent delete
        # after create/update is the same code-path as a delete event
        with db_api.context_manager.independent.reader.using(context):
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
        LOG.debug("Dispatching RPC callback event %s for %s %s.",
                  rpc_event, self._resource, resource_id)
        self._resource_push_api.push(context, [obj], rpc_event)

    def _extract_resource_id(self, callback_kwargs):
        id_kwarg = '%s_id' % self._resource
        if id_kwarg in callback_kwargs:
            return callback_kwargs[id_kwarg]
        if self._resource in callback_kwargs:
            return callback_kwargs[self._resource]['id']
        raise RuntimeError("Couldn't find resource ID in callback event")


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
