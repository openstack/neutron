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
from oslo_log import log as logging

from neutron.services.trunk import constants as trunk_consts
from neutron.services.trunk.rpc import server

LOG = logging.getLogger(__name__)


@registry.has_registry_receivers
class ServerSideRpcBackend(object):
    """The Neutron Server RPC backend."""

    def __init__(self):
        """Initialize an RPC backend for the Neutron Server."""
        self._skeleton = server.TrunkSkeleton()
        self._stub = server.TrunkStub()

        LOG.debug("RPC backend initialized for trunk plugin")

    # Set up listeners to trunk events: they dispatch RPC messages
    # to agents as needed. These are designed to work with any
    # agent-based driver that may integrate with the trunk service
    # plugin, e.g. linux bridge or ovs.
    @registry.receives(trunk_consts.TRUNK,
                       [events.AFTER_CREATE, events.AFTER_DELETE])
    @registry.receives(trunk_consts.SUBPORTS,
                       [events.AFTER_CREATE, events.AFTER_DELETE])
    def process_event(self, resource, event, trunk_plugin, payload):
        """Emit RPC notifications to registered subscribers."""
        context = payload.context
        LOG.debug("RPC notification needed for trunk %s", payload.trunk_id)
        if resource == trunk_consts.SUBPORTS:
            payload = payload.subports
            method = {
                events.AFTER_CREATE: self._stub.subports_added,
                events.AFTER_DELETE: self._stub.subports_deleted,
            }
        elif resource == trunk_consts.TRUNK:
            # On AFTER_DELETE event, current_trunk is None
            payload = payload.current_trunk or payload.original_trunk
            method = {
                events.AFTER_CREATE: self._stub.trunk_created,
                events.AFTER_DELETE: self._stub.trunk_deleted,
            }
        LOG.debug("Emitting event %s for resource %s", event, resource)
        method[event](context, payload)
