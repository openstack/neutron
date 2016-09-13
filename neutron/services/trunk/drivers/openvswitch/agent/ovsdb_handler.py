# Copyright (c) 2016 SUSE Linux Products GmbH
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

import functools

import eventlet
from oslo_concurrency import lockutils
from oslo_context import context
from oslo_log import log as logging
import oslo_messaging
from oslo_serialization import jsonutils

from neutron._i18n import _, _LE
from neutron.agent.common import ovs_lib
from neutron.api.rpc.handlers import resources_rpc
from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.common import utils as common_utils
from neutron import context as n_context
from neutron.plugins.ml2.drivers.openvswitch.agent.common \
    import constants as ovs_agent_constants
from neutron.services.trunk import constants
from neutron.services.trunk.drivers.openvswitch.agent \
    import trunk_manager as tman
from neutron.services.trunk.drivers.openvswitch import constants as t_const
from neutron.services.trunk.drivers.openvswitch import utils
from neutron.services.trunk.rpc import agent

LOG = logging.getLogger(__name__)

WAIT_FOR_PORT_TIMEOUT = 60


def lock_on_bridge_name(required_parameter):
    def func_decor(f):
        try:
            br_arg_index = f.__code__.co_varnames.index(required_parameter)
        except ValueError:
            raise RuntimeError(_("%s parameter is required for this decorator")
                               % required_parameter)

        @functools.wraps(f)
        def inner(*args, **kwargs):
            try:
                bridge_name = kwargs[required_parameter]
            except KeyError:
                bridge_name = args[br_arg_index]
            with lockutils.lock(bridge_name):
                return f(*args, **kwargs)
        return inner
    return func_decor


def is_trunk_bridge(port_name):
    return port_name.startswith(t_const.TRUNK_BR_PREFIX)


def is_trunk_service_port(port_name):
    """True if the port is any of the ports used to realize a trunk."""
    return is_trunk_bridge(port_name) or port_name[:2] in (
        tman.TrunkParentPort.DEV_PREFIX,
        tman.SubPort.DEV_PREFIX)


def bridge_has_instance_port(bridge):
    """True if there is an OVS port that doesn't have bridge or patch ports
       prefix.
    """
    try:
        ifaces = bridge.get_iface_name_list()
    except RuntimeError as e:
        LOG.error(_LE("Cannot obtain interface list for bridge %(bridge)s: "
                      "%(err)s"),
                  {'bridge': bridge.br_name,
                   'err': e})
        return False

    return any(iface for iface in ifaces
               if not is_trunk_service_port(iface))


class OVSDBHandler(object):
    """It listens to OVSDB events to create the physical resources associated
    to a logical trunk in response to OVSDB events (such as VM boot and/or
    delete).
    """

    def __init__(self, trunk_manager):
        self._context = n_context.get_admin_context_without_session()
        self.trunk_manager = trunk_manager
        self.trunk_rpc = agent.TrunkStub()

        registry.subscribe(self.process_trunk_port_events,
                           ovs_agent_constants.OVSDB_RESOURCE,
                           events.AFTER_READ)

    @property
    def context(self):
        self._context.request_id = context.generate_request_id()
        return self._context

    def process_trunk_port_events(
            self, resource, event, trigger, ovsdb_events):
        """Process added and removed port events coming from OVSDB monitor."""
        for port_event in ovsdb_events['added']:
            port_name = port_event['name']
            if is_trunk_bridge(port_name):
                LOG.debug("Processing trunk bridge %s", port_name)
                # As there is active waiting for port to appear, it's handled
                # in a separate greenthread.
                # NOTE: port_name is equal to bridge_name at this point.
                eventlet.spawn_n(self.handle_trunk_add, port_name)

        for port_event in ovsdb_events['removed']:
            bridge_name = port_event['external_ids'].get('bridge_name')
            if bridge_name and is_trunk_bridge(bridge_name):
                eventlet.spawn_n(
                    self.handle_trunk_remove, bridge_name, port_event)

    @lock_on_bridge_name(required_parameter='bridge_name')
    def handle_trunk_add(self, bridge_name):
        """Create trunk bridge based on parent port ID.

        This method is decorated with a lock that prevents processing deletion
        while creation hasn't been finished yet. It's based on the bridge name
        so we can keep processing other bridges in parallel.

        :param bridge_name: Name of the created trunk bridge.
        """
        # Wait for the VM's port, i.e. the trunk parent port, to show up.
        # If the VM fails to show up, i.e. this fails with a timeout,
        # then we clean the dangling bridge.
        bridge = ovs_lib.OVSBridge(bridge_name)

        # Handle condition when there was bridge in both added and removed
        # events and handle_trunk_remove greenthread was executed before
        # handle_trunk_add
        if not bridge.bridge_exists(bridge_name):
            LOG.debug("The bridge %s was deleted before it was handled.",
                      bridge_name)
            return

        bridge_has_port_predicate = functools.partial(
            bridge_has_instance_port, bridge)
        try:
            common_utils.wait_until_true(
                bridge_has_port_predicate,
                timeout=WAIT_FOR_PORT_TIMEOUT)
        except eventlet.TimeoutError:
            LOG.error(
                _LE('No port appeared on trunk bridge %(br_name)s '
                    'in %(timeout)d seconds. Cleaning up the bridge'),
                {'br_name': bridge.br_name,
                 'timeout': WAIT_FOR_PORT_TIMEOUT})
            bridge.destroy()
            return

        # Once we get hold of the trunk parent port, we can provision
        # the OVS dataplane for the trunk.
        try:
            self._wire_trunk(bridge, self._get_parent_port(bridge))
        except oslo_messaging.MessagingException as e:
            LOG.error(_LE("Got messaging error while processing trunk bridge "
                          "%(bridge_name)s: %(err)s"),
                      {'bridge_name': bridge.br_name,
                       'err': e})
        except RuntimeError as e:
            LOG.error(_LE("Failed to get parent port for bridge "
                          "%(bridge_name)s: %(err)s"),
                      {'bridge_name': bridge.br_name,
                       'err': e})

    @lock_on_bridge_name(required_parameter='bridge_name')
    def handle_trunk_remove(self, bridge_name, port):
        """Remove wiring between trunk bridge and integration bridge.

        The method calls into trunk manager to remove patch ports on
        integration bridge side and to delete the trunk bridge. It's decorated
        with a lock to prevent deletion of bridge while creation is still in
        process.

        :param bridge_name: Name of the bridge used for locking purposes.
        :param port: Parent port dict.
        """
        try:
            parent_port_id, trunk_id, subport_ids = self._get_trunk_metadata(
                port)
            self.unwire_subports_for_trunk(trunk_id, subport_ids)
            self.trunk_manager.remove_trunk(trunk_id, parent_port_id)
        except tman.TrunkManagerError as te:
            LOG.error(_LE("Removing trunk %(trunk_id)s failed: %(err)s"),
                      {'trunk_id': port['external_ids']['trunk_id'],
                       'err': te})
        else:
            LOG.debug("Deleted resources associated to trunk: %s", trunk_id)

    def manages_this_trunk(self, trunk_id):
        """True if this OVSDB handler manages trunk based on given ID."""
        bridge_name = utils.gen_trunk_br_name(trunk_id)
        return ovs_lib.BaseOVS().bridge_exists(bridge_name)

    def wire_subports_for_trunk(self, context, trunk_id, subports,
                                trunk_bridge=None, parent_port=None):
        """Create OVS ports associated to the logical subports."""
        # Tell the server that subports must be bound to this host.
        subport_bindings = self.trunk_rpc.update_subport_bindings(
            context, subports)

        # Bindings were successful: create the OVS subports.
        subport_bindings = subport_bindings.get(trunk_id, [])
        subports_mac = {p['id']: p['mac_address'] for p in subport_bindings}
        subport_ids = []
        for subport in subports:
            try:
                self.trunk_manager.add_sub_port(trunk_id, subport.port_id,
                                                subports_mac[subport.port_id],
                                                subport.segmentation_id)
            except tman.TrunkManagerError as te:
                LOG.error(_LE("Failed to add subport with port ID "
                              "%(subport_port_id)s to trunk with ID "
                              "%(trunk_id)s: %(err)s"),
                          {'subport_port_id': subport.port_id,
                           'trunk_id': trunk_id,
                           'err': te})
            else:
                subport_ids.append(subport.port_id)

        try:
            self._set_trunk_metadata(
                trunk_bridge, parent_port, trunk_id, subport_ids)
        except RuntimeError:
            LOG.error(_LE("Failed to set metadata for trunk %s"), trunk_id)
            # NOTE(status_police): Trunk bridge has missing metadata now, it
            # will cause troubles during deletion.
            # TODO(jlibosva): Investigate how to proceed during removal of
            # trunk bridge that doesn't have metadata stored and whether it's
            # wise to set DEGRADED status in case we don't have metadata
            # present on the bridge.
            self.trunk_rpc.update_trunk_status(
                context, trunk_id, constants.DEGRADED_STATUS)
            return

        # Set trunk status to DEGRADED if not all subports were created
        # succesfully
        status = (constants.ACTIVE_STATUS if len(subport_ids) == len(subports)
                  else constants.DEGRADED_STATUS)
        # NOTE(status_police): Set trunk status to ACTIVE if all subports were
        # added successfully. If some port wasn't added, trunk is set to
        # DEGRADED.
        self.trunk_rpc.update_trunk_status(
            context, trunk_id, status)

        LOG.debug("Added trunk: %s", trunk_id)

    def unwire_subports_for_trunk(self, trunk_id, subport_ids):
        """Destroy OVS ports associated to the logical subports."""
        for subport_id in subport_ids:
            try:
                self.trunk_manager.remove_sub_port(trunk_id, subport_id)
            except tman.TrunkManagerError as te:
                LOG.error(_LE("Removing subport %(subport_id)s from trunk "
                              "%(trunk_id)s failed: %(err)s"),
                          {'subport_id': subport_id,
                           'trunk_id': trunk_id,
                           'err': te})

    def _get_parent_port(self, trunk_bridge):
        """Return the OVS trunk parent port plugged on trunk_bridge."""
        trunk_br_ports = trunk_bridge.get_ports_attributes(
            'Interface', columns=['name', 'external_ids'],
            if_exists=True)
        for trunk_br_port in trunk_br_ports:
            if not is_trunk_service_port(trunk_br_port['name']):
                return trunk_br_port
        raise RuntimeError(
            "Can't find parent port for trunk bridge %s" %
            trunk_bridge.br_name)

    def _wire_trunk(self, trunk_br, port):
        """Wire trunk bridge with integration bridge.

        The method calls into trunk manager to create patch ports for trunk and
        patch ports for all subports associated with this trunk.

        :param trunk_br: OVSBridge object representing the trunk bridge.
        :param port: Parent port dict.
        """
        ctx = self.context
        try:
            parent_port_id = (
                self.trunk_manager.get_port_uuid_from_external_ids(port))
            trunk = self.trunk_rpc.get_trunk_details(ctx, parent_port_id)
        except tman.TrunkManagerError as te:
            LOG.error(_LE("Can't obtain parent port ID from port %s"),
                      port['name'])
            return
        except resources_rpc.ResourceNotFound:
            LOG.error(_LE("Port %s has no trunk associated."), parent_port_id)
            return

        try:
            self.trunk_manager.create_trunk(
                trunk.id, trunk.port_id,
                port['external_ids'].get('attached-mac'))
        except tman.TrunkManagerError as te:
            LOG.error(_LE("Failed to create trunk %(trunk_id)s: %(err)s"),
                      {'trunk_id': trunk.id,
                       'err': te})
            # NOTE(status_police): Trunk couldn't be created so it ends in
            # ERROR status and resync can fix that later.
            self.trunk_rpc.update_trunk_status(context, trunk.id,
                                               constants.ERROR_STATUS)
            return

        self.wire_subports_for_trunk(
            ctx, trunk.id, trunk.sub_ports, trunk_bridge=trunk_br,
            parent_port=port)

    def _set_trunk_metadata(self, trunk_bridge, port, trunk_id, subport_ids):
        """Set trunk metadata in OVS port for trunk parent port."""
        # update the parent port external_ids to store the trunk bridge
        # name, trunk id and subport ids so we can easily remove the trunk
        # bridge and service ports once this port is removed
        trunk_bridge = trunk_bridge or ovs_lib.OVSBridge(
            utils.gen_trunk_br_name(trunk_id))
        port = port or self._get_parent_port(trunk_bridge)

        port['external_ids']['bridge_name'] = trunk_bridge.br_name
        port['external_ids']['trunk_id'] = trunk_id
        port['external_ids']['subport_ids'] = jsonutils.dumps(subport_ids)
        trunk_bridge.set_db_attribute(
            'Interface', port['name'], 'external_ids', port['external_ids'])

    def _get_trunk_metadata(self, port):
        """Get trunk metadata from OVS port."""
        parent_port_id = (
            self.trunk_manager.get_port_uuid_from_external_ids(port))
        trunk_id = port['external_ids']['trunk_id']
        subport_ids = jsonutils.loads(port['external_ids']['subport_ids'])

        return parent_port_id, trunk_id, subport_ids
