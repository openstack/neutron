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

from neutron_lib.api.definitions import portbindings
from neutron_lib.db import api as db_api
from neutron_lib.plugins import directory
from neutron_lib import rpc as n_rpc
from neutron_lib.services.trunk import constants as trunk_consts
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
import oslo_messaging
from sqlalchemy.orm import exc

from neutron.api.rpc.callbacks import events
from neutron.api.rpc.callbacks.producer import registry
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import resources_rpc
from neutron.common import utils as common_utils
from neutron.objects import trunk as trunk_objects
from neutron.services.trunk import exceptions as trunk_exc
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

    def __init__(self):
        # Used to provide trunk lookups for the agent.
        registry.provide(trunk_by_port_provider, resources.TRUNK)
        self._connection = n_rpc.Connection()
        self._connection.create_consumer(
            constants.TRUNK_BASE_TOPIC, [self], fanout=False)
        self._connection.consume_in_threads()

    @property
    def core_plugin(self):
        if not self._core_plugin:
            self._core_plugin = directory.get_plugin()
        return self._core_plugin

    @log_helpers.log_method_call
    def update_subport_bindings(self, context, subports):
        """Update subport bindings to match trunk host binding."""
        el = common_utils.get_elevated_context(context)
        ports_by_trunk_id = collections.defaultdict(list)
        updated_ports = collections.defaultdict(list)

        for s in subports:
            ports_by_trunk_id[s['trunk_id']].append(s['port_id'])
        for trunk_id, subport_ids in ports_by_trunk_id.items():
            trunk = trunk_objects.Trunk.get_object(el, id=trunk_id)
            if not trunk:
                LOG.debug("Trunk not found. id: %s", trunk_id)
                continue

            trunk_updated_ports = self._process_trunk_subport_bindings(
                                                                  el,
                                                                  trunk,
                                                                  subport_ids)
            updated_ports[trunk.id].extend(trunk_updated_ports)

        return updated_ports

    def _safe_update_trunk(self, trunk, **kwargs):
        for try_cnt in range(db_api.MAX_RETRIES):
            try:
                trunk.update(**kwargs)
                break
            except exc.StaleDataError as e:
                if try_cnt < db_api.MAX_RETRIES - 1:
                    LOG.debug("Got StaleDataError exception: %s", e)
                    continue
                # re-raise when all tries failed
                raise

    def update_trunk_status(self, context, trunk_id, status):
        """Update the trunk status to reflect outcome of data plane wiring."""
        with db_api.CONTEXT_WRITER.using(context):
            trunk = trunk_objects.Trunk.get_object(context, id=trunk_id)
            if trunk:
                self._safe_update_trunk(trunk, status=status)

    def _process_trunk_subport_bindings(self, context, trunk, port_ids):
        """Process port bindings for subports on the given trunk."""
        updated_ports = []
        trunk_port_id = trunk.port_id
        trunk_port = self.core_plugin.get_port(context, trunk_port_id)
        trunk_host = trunk_port.get(portbindings.HOST_ID)
        migrating_to_host = trunk_port.get(
            portbindings.PROFILE, {}).get('migrating_to')
        if migrating_to_host and trunk_host != migrating_to_host:
            # Trunk is migrating now, so lets update host of the subports
            # to the new host already
            trunk_host = migrating_to_host

        # NOTE(status_police) Set the trunk in BUILD state before
        # processing subport bindings. The trunk will stay in BUILD
        # state until an attempt has been made to bind all subports
        # passed here and the agent acknowledges the operation was
        # successful.
        self._safe_update_trunk(
            trunk, status=trunk_consts.TRUNK_BUILD_STATUS)

        for port_id in port_ids:
            try:
                updated_port = self._handle_port_binding(context, port_id,
                                                         trunk, trunk_host)
                # NOTE(fitoduarte): consider trimming down the content
                # of the port data structure.
                updated_ports.append(updated_port)
            except trunk_exc.SubPortBindingError as e:
                LOG.error("Failed to bind subport: %s", e)

                # NOTE(status_police) The subport binding has failed in a
                # manner in which we cannot proceed and the user must take
                # action to bring the trunk back to a sane state.
                self._safe_update_trunk(
                    trunk, status=trunk_consts.TRUNK_ERROR_STATUS)
                return []
            except Exception as e:
                msg = ("Failed to bind subport port %(port)s on trunk "
                       "%(trunk)s: %(exc)s")
                LOG.error(msg, {'port': port_id, 'trunk': trunk.id, 'exc': e})

        if len(port_ids) != len(updated_ports):
            self._safe_update_trunk(
                trunk, status=trunk_consts.TRUNK_DEGRADED_STATUS)

        return updated_ports

    def _handle_port_binding(self, context, port_id, trunk, trunk_host):
        """Bind the given port to the given host.

           :param context: The context to use for the operation
           :param port_id: The UUID of the port to be bound
           :param trunk: The trunk that the given port belongs to
           :param trunk_host: The host to bind the given port to
        """
        port = self.core_plugin.update_port(
            context, port_id,
            {'port': {portbindings.HOST_ID: trunk_host,
                      'device_owner': trunk_consts.TRUNK_SUBPORT_OWNER}})
        vif_type = port.get(portbindings.VIF_TYPE)
        if vif_type == portbindings.VIF_TYPE_BINDING_FAILED:
            raise trunk_exc.SubPortBindingError(port_id=port_id,
                                                trunk_id=trunk.id)
        return port


class TrunkStub(object):
    """Stub proxy code for server->agent communication."""

    def __init__(self):
        self._resource_rpc = resources_rpc.ResourcesPushRpcApi()

    @log_helpers.log_method_call
    def trunk_created(self, context, trunk):
        """Tell the agent about a trunk being created."""
        self._resource_rpc.push(context, [trunk], events.CREATED)

    @log_helpers.log_method_call
    def trunk_deleted(self, context, trunk):
        """Tell the agent about a trunk being deleted."""
        self._resource_rpc.push(context, [trunk], events.DELETED)

    @log_helpers.log_method_call
    def subports_added(self, context, subports):
        """Tell the agent about new subports to add."""
        self._resource_rpc.push(context, subports, events.CREATED)

    @log_helpers.log_method_call
    def subports_deleted(self, context, subports):
        """Tell the agent about existing subports to remove."""
        self._resource_rpc.push(context, subports, events.DELETED)
