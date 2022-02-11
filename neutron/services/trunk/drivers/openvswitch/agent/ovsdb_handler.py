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
import time

import eventlet
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import context as n_context
from neutron_lib.services.trunk import constants
from oslo_concurrency import lockutils
from oslo_context import context as o_context
from oslo_log import log as logging
import oslo_messaging
from oslo_serialization import jsonutils

from neutron._i18n import _
from neutron.agent.common import ovs_lib
from neutron.api.rpc.handlers import resources_rpc
from neutron.common import utils as common_utils
from neutron.plugins.ml2.drivers.openvswitch.agent.common \
    import constants as ovs_agent_constants
from neutron.services.trunk.drivers.openvswitch.agent import exceptions
from neutron.services.trunk.drivers.openvswitch.agent \
    import trunk_manager as tman
from neutron.services.trunk.drivers.openvswitch import constants as t_const
from neutron.services.trunk.drivers.openvswitch import utils
from neutron.services.trunk.rpc import agent

LOG = logging.getLogger(__name__)

DEFAULT_WAIT_FOR_PORT_TIMEOUT = 60
WAIT_BEFORE_TRUNK_DELETE = 6


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


def is_subport(port_name):
    return port_name.startswith(tman.SubPort.DEV_PREFIX)


def is_trunk_service_port(port_name):
    """True if the port is any of the ports used to realize a trunk."""
    return is_trunk_bridge(port_name) or port_name[:2] in (
        tman.TrunkParentPort.DEV_PREFIX,
        tman.SubPort.DEV_PREFIX)


def bridge_has_port(bridge, is_port_predicate):
    """True if there is an OVS port for which is_port_predicate is True.
    """
    try:
        ifaces = bridge.get_iface_name_list()
    except RuntimeError as e:
        LOG.error("Cannot obtain interface list for bridge %(bridge)s: "
                  "%(err)s",
                  {'bridge': bridge.br_name,
                   'err': e})
        return False

    return any(iface for iface in ifaces if is_port_predicate(iface))


def bridge_has_instance_port(bridge):
    """True if there is an OVS port that doesn't have bridge or patch ports
       prefix.
    """
    is_instance_port = lambda p: not is_trunk_service_port(p)
    return bridge_has_port(bridge, is_instance_port)


def bridge_has_service_port(bridge):
    """True if there is an OVS port that is used to implement a trunk.
    """
    return bridge_has_port(bridge, is_trunk_service_port)


@registry.has_registry_receivers
class OVSDBHandler(object):
    """It listens to OVSDB events to create the physical resources associated
    to a logical trunk in response to OVSDB events (such as VM boot and/or
    delete).
    """

    def __init__(self, trunk_manager):
        self.timeout = DEFAULT_WAIT_FOR_PORT_TIMEOUT
        self._context = n_context.get_admin_context_without_session()
        self.trunk_manager = trunk_manager
        self.trunk_rpc = agent.TrunkStub()

    @property
    def context(self):
        self._context.request_id = o_context.generate_request_id()
        return self._context

    @registry.receives(ovs_agent_constants.OVSDB_RESOURCE, [events.AFTER_READ])
    def process_trunk_port_events(
            self, resource, event, trigger, payload):
        """Process added and removed port events coming from OVSDB monitor."""
        ovsdb_events = payload.latest_state
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
        bridge = ovs_lib.OVSBridge(bridge_name)
        # Handle condition when there was bridge in both added and removed
        # events and handle_trunk_remove greenthread was executed before
        # handle_trunk_add
        if not bridge.bridge_exists(bridge_name):
            LOG.debug("The bridge %s was deleted before it was handled.",
                      bridge_name)
            return

        # Determine the state of the trunk bridge by looking for the VM's port,
        # i.e. the trunk parent port and/or patch ports to be present. If the
        # VM is absent, then we clean the dangling bridge. If the VM is present
        # the value of 'rewire' tells us whether or not the bridge was dealt
        # with in a previous added event, and thus it has active patch ports.
        if not self._is_vm_connected(bridge):
            LOG.debug("No instance port associated to bridge %s could be "
                      "found. Deleting bridge and its resources.", bridge_name)
            self.trunk_manager.dispose_trunk(bridge)
            return

        # Check if the trunk was provisioned in a previous run. This can happen
        # at agent startup when existing trunks are notified as added events.
        rewire = bridge_has_service_port(bridge)
        # Once we get hold of the trunk parent port, we can provision
        # the OVS dataplane for the trunk.
        try:
            self._wire_trunk(bridge, self._get_parent_port(bridge), rewire)
        except oslo_messaging.MessagingException as e:
            LOG.error("Got messaging error while processing trunk bridge "
                      "%(bridge_name)s: %(err)s",
                      {'bridge_name': bridge.br_name,
                       'err': e})
        except exceptions.ParentPortNotFound as e:
            LOG.error("Failed to get parent port for bridge "
                      "%(bridge_name)s: %(err)s",
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
        # TODO(njohnston): In the case of DPDK with trunk ports, if nova
        # deletes an interface and then re-adds it we can get a race
        # condition where the port is re-added and then the bridge is
        # deleted because we did not properly catch the re-addition.  To
        # solve this would require transitioning to ordered event
        # resolution, like the L3 agent does with the
        # ResourceProcessingQueue class.  Until we can make that happen, we
        # try to mitigate the issue by checking if there is a port on the
        # bridge and if so then do not remove it.
        bridge = ovs_lib.OVSBridge(bridge_name)
        time.sleep(WAIT_BEFORE_TRUNK_DELETE)
        if bridge_has_instance_port(bridge):
            LOG.debug("The bridge %s has instances attached so it will not "
                      "be deleted.", bridge_name)
            return
        try:
            # TODO(jlibosva): Investigate how to proceed during removal of
            # trunk bridge that doesn't have metadata stored.
            parent_port_id, trunk_id, subport_ids = self._get_trunk_metadata(
                port)
            # NOTE(status_police): we do not report changes in trunk status on
            # removal to avoid potential races between agents in case the event
            # is due to a live migration or reassociation of a trunk to a new
            # VM.
            self.unwire_subports_for_trunk(trunk_id, subport_ids)
            self.trunk_manager.remove_trunk(trunk_id, parent_port_id)
        except tman.TrunkManagerError as te:
            LOG.error("Removing trunk %(trunk_id)s failed: %(err)s",
                      {'trunk_id': port['external_ids']['trunk_id'],
                       'err': te})
        else:
            LOG.debug("Deleted resources associated to trunk: %s", trunk_id)

    def manages_this_trunk(self, trunk_id):
        """True if this OVSDB handler manages trunk based on given ID."""
        bridge_name = utils.gen_trunk_br_name(trunk_id)
        return ovs_lib.BaseOVS().bridge_exists(bridge_name)

    def get_connected_subports_for_trunk(self, trunk_id):
        """Return the list of subports present on the trunk bridge."""
        bridge = ovs_lib.OVSBridge(utils.gen_trunk_br_name(trunk_id))
        if not bridge.bridge_exists(bridge.br_name):
            return []
        try:
            ports = bridge.get_ports_attributes(
                            'Interface', columns=['name', 'external_ids'])
            return [
                self.trunk_manager.get_port_uuid_from_external_ids(port)
                for port in ports if is_subport(port['name'])
            ]
        except (RuntimeError, tman.TrunkManagerError) as e:
            LOG.error("Failed to get subports for bridge %(bridge)s: "
                      "%(err)s", {'bridge': bridge.br_name, 'err': e})
            return []

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
                LOG.error("Failed to add subport with port ID "
                          "%(subport_port_id)s to trunk with ID "
                          "%(trunk_id)s: %(err)s",
                          {'subport_port_id': subport.port_id,
                           'trunk_id': trunk_id,
                           'err': te})
            else:
                subport_ids.append(subport.port_id)

        try:
            self._update_trunk_metadata(
                trunk_bridge, parent_port, trunk_id, subport_ids)
        except (RuntimeError, exceptions.ParentPortNotFound) as e:
            LOG.error("Failed to store metadata for trunk %(trunk_id)s: "
                      "%(reason)s", {'trunk_id': trunk_id, 'reason': e})
            # NOTE(status_police): Trunk bridge has stale metadata now, it
            # might cause troubles during deletion. Signal a DEGRADED status;
            # if the user undo/redo the operation things may go back to
            # normal.
            return constants.TRUNK_DEGRADED_STATUS

        LOG.debug("Added trunk: %s", trunk_id)
        return self._get_current_status(subports, subport_ids)

    def unwire_subports_for_trunk(self, trunk_id, subport_ids):
        """Destroy OVS ports associated to the logical subports."""
        ids = []
        for subport_id in subport_ids:
            try:
                self.trunk_manager.remove_sub_port(trunk_id, subport_id)
                ids.append(subport_id)
            except tman.TrunkManagerError as te:
                LOG.error("Removing subport %(subport_id)s from trunk "
                          "%(trunk_id)s failed: %(err)s",
                          {'subport_id': subport_id,
                           'trunk_id': trunk_id,
                           'err': te})
        try:
            # OVS bridge and port to be determined by _update_trunk_metadata
            bridge = None
            port = None
            self._update_trunk_metadata(
                bridge, port, trunk_id, subport_ids, wire=False)
        except RuntimeError as e:
            # NOTE(status_police): Trunk bridge has stale metadata now, it
            # might cause troubles during deletion. Signal a DEGRADED status;
            # if the user undo/redo the operation things may go back to
            # normal.
            LOG.error("Failed to store metadata for trunk %(trunk_id)s: "
                      "%(reason)s", {'trunk_id': trunk_id, 'reason': e})
            return constants.TRUNK_DEGRADED_STATUS
        except exceptions.ParentPortNotFound as e:
            # If a user deletes/migrates a VM and remove subports from a trunk
            # in short sequence, there is a chance that we hit this spot in
            # that the trunk may still be momentarily bound to the agent. We
            # should not mark the status as DEGRADED in this case.
            LOG.debug(e)

        return self._get_current_status(subport_ids, ids)

    def report_trunk_status(self, context, trunk_id, status):
        """Report trunk status to the server."""
        self.trunk_rpc.update_trunk_status(context, trunk_id, status)

    def _get_parent_port(self, trunk_bridge):
        """Return the OVS trunk parent port plugged on trunk_bridge."""
        trunk_br_ports = trunk_bridge.get_ports_attributes(
            'Interface', columns=['name', 'external_ids'],
            if_exists=True)
        for trunk_br_port in trunk_br_ports:
            if not is_trunk_service_port(trunk_br_port['name']):
                return trunk_br_port
        raise exceptions.ParentPortNotFound(bridge=trunk_bridge.br_name)

    def _wire_trunk(self, trunk_br, port, rewire=False):
        """Wire trunk bridge with integration bridge.

        The method calls into trunk manager to create patch ports for trunk and
        patch ports for all subports associated with this trunk. If rewire is
        True, a diff is performed between desired state (the one got from the
        server) and actual state (the patch ports present on the trunk bridge)
        and subports are wired/unwired accordingly.

        :param trunk_br: OVSBridge object representing the trunk bridge.
        :param port: Parent port dict.
        :param rewire: True if local trunk state must be reconciled with
            server's state.
        """
        ctx = self.context
        try:
            parent_port_id = (
                self.trunk_manager.get_port_uuid_from_external_ids(port))
            trunk = self.trunk_rpc.get_trunk_details(ctx, parent_port_id)
        except tman.TrunkManagerError:
            LOG.error("Can't obtain parent port ID from port %s",
                      port['name'])
            return
        except resources_rpc.ResourceNotFound:
            LOG.error("Port %s has no trunk associated.", parent_port_id)
            return

        try:
            registry.publish(
                resources.TRUNK, events.BEFORE_CREATE, self,
                payload=events.DBEventPayload(ctx, resource_id=trunk.id,
                                              desired_state=trunk))
            self.trunk_manager.create_trunk(
                trunk.id, trunk.port_id,
                port['external_ids'].get('attached-mac'))
        except tman.TrunkManagerError as te:
            LOG.error("Failed to create trunk %(trunk_id)s: %(err)s",
                      {'trunk_id': trunk.id,
                       'err': te})
            # NOTE(status_police): Trunk couldn't be created so it ends in
            # ERROR status and resync can fix that later.
            self.report_trunk_status(
                ctx, trunk.id, constants.TRUNK_ERROR_STATUS)
            return

        # We need to remove stale subports
        unwire_status = constants.TRUNK_ACTIVE_STATUS
        if rewire:
            old_subport_ids = self.get_connected_subports_for_trunk(trunk.id)
            subports = {p['port_id'] for p in trunk.sub_ports}
            subports_to_delete = set(old_subport_ids) - subports
            if subports_to_delete:
                unwire_status = self.unwire_subports_for_trunk(
                    trunk.id, subports_to_delete)

        # NOTE(status_police): inform the server whether the operation
        # was a partial or complete success. Do not inline status.
        # NOTE: in case of rewiring we readd ports that are already present on
        # the bridge because e.g. the segmentation ID might have changed (e.g.
        # agent crashed, port was removed and readded with a different seg ID)
        wire_status = self.wire_subports_for_trunk(
            ctx, trunk.id, trunk.sub_ports,
            trunk_bridge=trunk_br, parent_port=port)

        if (unwire_status == wire_status and
                wire_status == constants.TRUNK_ACTIVE_STATUS):
            status = constants.TRUNK_ACTIVE_STATUS
        else:
            status = constants.TRUNK_DEGRADED_STATUS
        self.report_trunk_status(ctx, trunk.id, status)

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
        trunk_id = port['external_ids'].get('trunk_id')
        subport_ids = jsonutils.loads(
            port['external_ids'].get('subport_ids', '[]'))

        return parent_port_id, trunk_id, subport_ids

    def _update_trunk_metadata(self, trunk_bridge, port,
                               trunk_id, subport_ids, wire=True):
        """Update trunk metadata.

        :param trunk_bridge: OVS trunk bridge.
        :param port: OVS parent port.
        :param trunk_id: trunk ID.
        :param subport_ids: subports affecting the metadata.
        :param wire: if True subport_ids are added, otherwise removed.
        """
        trunk_bridge = trunk_bridge or ovs_lib.OVSBridge(
            utils.gen_trunk_br_name(trunk_id))
        port = port or self._get_parent_port(trunk_bridge)
        _port_id, _trunk_id, old_subports = self._get_trunk_metadata(port)
        if wire:
            new_subports = set(old_subports) | set(subport_ids)
        else:
            new_subports = set(old_subports) - set(subport_ids)
        self._set_trunk_metadata(trunk_bridge, port, trunk_id, new_subports)

    def _get_current_status(self, expected_subports, actual_subports):
        """Return the current status of the trunk.

        If the number of expected subports to be processed does not match the
        number of subports successfully processed, the status returned is
        DEGRADED, ACTIVE otherwise.
        """
        # NOTE(status_police): a call to this method should be followed by
        # a trunk_update_status to report the latest trunk status, but there
        # can be exceptions (e.g. unwire_subports_for_trunk).
        if len(expected_subports) != len(actual_subports):
            return constants.TRUNK_DEGRADED_STATUS
        else:
            return constants.TRUNK_ACTIVE_STATUS

    def _is_vm_connected(self, bridge):
        """True if an instance is connected to bridge, False otherwise."""
        bridge_has_port_predicate = functools.partial(
            bridge_has_instance_port, bridge)
        try:
            common_utils.wait_until_true(
                bridge_has_port_predicate,
                timeout=self.timeout)
            return True
        except common_utils.WaitTimeout:
            LOG.error(
                'No port present on trunk bridge %(br_name)s '
                'in %(timeout)d seconds.',
                {'br_name': bridge.br_name,
                 'timeout': self.timeout})
        return False
