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

import collections

from oslo_log import log as logging
import oslo_messaging

from neutron.api.rpc.callbacks import events
from neutron.api.rpc.callbacks.producer import registry
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import resources_rpc
from neutron.common import rpc as n_rpc
from neutron.db import api as db_api
from neutron.extensions import portbindings
from neutron import manager
from neutron.objects import trunk as trunk_objects
from neutron.services.trunk.rpc import constants

LOG = logging.getLogger(__name__)

# This module contains stub (client-side) and skeleton (server-side)
# proxy code that executes in the Neutron server process space. This
# is needed if any of the trunk service plugin drivers has a remote
# component (e.g. agent), that needs to communicate with the Neutron
# Server.

# The Server side exposes the following remote methods:
#
# - lookup method to retrieve trunk details: used by the agent to learn
#   about the trunk.
# - update methods for trunk and its subports: used by the agent to
#   inform the server about local trunk status changes.
#
# For agent-side stub and skeleton proxy code, please look at agent.py


def trunk_by_port_provider(resource, port_id, context, **kwargs):
    """Provider callback to supply trunk information by parent port."""
    return trunk_objects.Trunk.get_object(context, port_id=port_id)


class TrunkSkeleton(object):
    """Skeleton proxy code for agent->server communication."""

    # API version history:
    # 1.0 Initial version
    target = oslo_messaging.Target(version='1.0',
                                   namespace=constants.TRUNK_BASE_NAMESPACE)

    _core_plugin = None
    _trunk_plugin = None

    def __init__(self):
        # Used to provide trunk lookups for the agent.
        registry.provide(trunk_by_port_provider, resources.TRUNK)
        self._connection = n_rpc.create_connection()
        self._connection.create_consumer(
            constants.TRUNK_BASE_TOPIC, [self], fanout=False)
        self._connection.consume_in_threads()

    @property
    def core_plugin(self):
        # TODO(armax): consider getting rid of this property if we
        # can get access to the Port object
        if not self._core_plugin:
            self._core_plugin = manager.NeutronManager.get_plugin()
        return self._core_plugin

    def update_subport_bindings(self, context, subports):
        """Update subport bindings to match trunk host binding."""
        el = context.elevated()
        ports_by_trunk_id = collections.defaultdict(list)
        updated_ports = collections.defaultdict(list)
        for s in subports:
            ports_by_trunk_id[s['trunk_id']].append(s['port_id'])
        for trunk_id, subport_ids in ports_by_trunk_id.items():
            trunk = trunk_objects.Trunk.get_object(el, id=trunk_id)
            if not trunk:
                LOG.debug("Trunk not found. id: %s", trunk_id)
                continue
            trunk_port_id = trunk.port_id
            trunk_port = self.core_plugin.get_port(el, trunk_port_id)
            trunk_host = trunk_port.get(portbindings.HOST_ID)
            for port_id in subport_ids:
                updated_port = self.core_plugin.update_port(
                    el, port_id, {'port': {portbindings.HOST_ID: trunk_host}})
                # NOTE(fitoduarte): consider trimming down the content
                # of the port data structure.
                updated_ports[trunk_id].append(updated_port)
        return updated_ports

    def update_trunk_status(self, context, trunk_id, status):
        """Update the trunk status to reflect outcome of data plane wiring."""
        with db_api.autonested_transaction(context.session):
            trunk = trunk_objects.Trunk.get_object(context, id=trunk_id)
            if trunk:
                trunk.status = status
                trunk.update()


class TrunkStub(object):
    """Stub proxy code for server->agent communication."""

    def __init__(self):
        self._resource_rpc = resources_rpc.ResourcesPushRpcApi()

    def trunk_created(self, context, trunk):
        """Tell the agent about a trunk being created."""
        self._resource_rpc.push(context, [trunk], events.CREATED)

    def trunk_deleted(self, context, trunk):
        """Tell the agent about a trunk being deleted."""
        self._resource_rpc.push(context, [trunk], events.DELETED)

    def subports_added(self, context, subports):
        """Tell the agent about new subports to add."""
        self._resource_rpc.push(context, subports, events.CREATED)

    def subports_deleted(self, context, subports):
        """Tell the agent about existing subports to remove."""
        self._resource_rpc.push(context, subports, events.DELETED)
