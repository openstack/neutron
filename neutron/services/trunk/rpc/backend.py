# Copyright 2016 Hewlett Packard Enterprise Development LP
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

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from oslo_log import log as logging

from neutron.services.trunk.rpc import server

LOG = logging.getLogger(__name__)


@registry.has_registry_receivers
class ServerSideRpcBackend:
    """The Neutron Server RPC backend."""

    def __init__(self):
        """Initialize an RPC backend for the Neutron Server."""
        self._stub = server.TrunkStub()

        LOG.debug("RPC notifier initialized for trunk plugin")

        for event_type in (events.AFTER_CREATE, events.AFTER_DELETE):
            registry.subscribe(self.process_event,
                               resources.TRUNK, event_type)
            registry.subscribe(self.process_event,
                               resources.SUBPORTS, event_type)

    # Set up listeners to trunk events: they dispatch RPC messages
    # to agents as needed. These are designed to work with any
    # agent-based driver that may integrate with the trunk service
    # plugin, e.g. ovs.

    def process_event(self, resource, event, trunk_plugin, payload):
        """Emit RPC notifications to registered subscribers."""
        context = payload.context
        LOG.debug("RPC notification needed for trunk %s", payload.resource_id)

        if resource == resources.TRUNK:
            payload = payload.latest_state
            method = {
                events.AFTER_CREATE: self._stub.trunk_created,
                events.AFTER_DELETE: self._stub.trunk_deleted,
            }
        elif resource == resources.SUBPORTS:
            payload = payload.metadata['subports']
            method = {
                events.AFTER_CREATE: self._stub.subports_added,
                events.AFTER_DELETE: self._stub.subports_deleted,
            }
        else:
            LOG.error('Wrong resource %s', resource)

        LOG.debug("Emitting event %s for resource %s", event, resource)
        method[event](context, payload)
