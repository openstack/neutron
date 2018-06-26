# Copyright (c) 2013 OpenStack Foundation
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

from neutron_lib.api.definitions import portbindings
from neutron_lib import constants
from neutron_lib.plugins.ml2 import api
from oslo_log import log
from oslo_serialization import jsonutils
import sqlalchemy

from neutron.db import segments_db

LOG = log.getLogger(__name__)


class InstanceSnapshot(object):
    """Used to avoid holding references to DB objects in PortContext."""
    def __init__(self, obj):
        self._model_class = obj.__class__
        self._identity_key = sqlalchemy.orm.util.identity_key(instance=obj)[1]
        self._cols = [col.key
                      for col in sqlalchemy.inspect(self._model_class).columns]
        for col in self._cols:
            setattr(self, col, getattr(obj, col))

    def persist_state_to_session(self, session):
        """Updates the state of the snapshot in the session.

        Finds the SQLA object in the session if it exists or creates a new
        object and updates the object with the column values stored in this
        snapshot.
        """
        db_obj = session.query(self._model_class).get(self._identity_key)
        if db_obj:
            for col in self._cols:
                setattr(db_obj, col, getattr(self, col))
        else:
            session.add(self._model_class(**{col: getattr(self, col)
                                             for col in self._cols}))

    def __getitem__(self, item):
        if item not in self._cols:
            raise KeyError(item)
        return getattr(self, item)


class MechanismDriverContext(object):
    """MechanismDriver context base class."""
    def __init__(self, plugin, plugin_context):
        self._plugin = plugin
        # This temporarily creates a reference loop, but the
        # lifetime of PortContext is limited to a single
        # method call of the plugin.
        self._plugin_context = plugin_context


class NetworkContext(MechanismDriverContext, api.NetworkContext):

    def __init__(self, plugin, plugin_context, network,
                 original_network=None, segments=None):
        super(NetworkContext, self).__init__(plugin, plugin_context)
        self._network = network
        self._original_network = original_network
        self._segments = segments_db.get_network_segments(
            plugin_context, network['id']) if segments is None else segments

    @property
    def current(self):
        return self._network

    @property
    def original(self):
        return self._original_network

    @property
    def network_segments(self):
        return self._segments


class SubnetContext(MechanismDriverContext, api.SubnetContext):

    def __init__(self, plugin, plugin_context, subnet, network,
                 original_subnet=None):
        super(SubnetContext, self).__init__(plugin, plugin_context)
        self._subnet = subnet
        self._original_subnet = original_subnet
        self._network_context = NetworkContext(plugin, plugin_context,
                                               network) if network else None

    @property
    def current(self):
        return self._subnet

    @property
    def original(self):
        return self._original_subnet

    @property
    def network(self):
        if self._network_context is None:
            network = self._plugin.get_network(
                self._plugin_context, self.current['network_id'])
            self._network_context = NetworkContext(
                self._plugin, self._plugin_context, network)
        return self._network_context


class PortContext(MechanismDriverContext, api.PortContext):

    def __init__(self, plugin, plugin_context, port, network, binding,
                 binding_levels, original_port=None):
        super(PortContext, self).__init__(plugin, plugin_context)
        self._port = port
        self._original_port = original_port
        if isinstance(network, NetworkContext):
            self._network_context = network
        else:
            self._network_context = NetworkContext(
                plugin, plugin_context, network) if network else None
        # NOTE(kevinbenton): InstanceSnapshot can go away once we are working
        # with OVO objects instead of native SQLA objects.
        self._binding = InstanceSnapshot(binding)
        self._binding_levels = binding_levels or []
        self._segments_to_bind = None
        self._new_bound_segment = None
        self._next_segments_to_bind = None
        if original_port:
            self._original_vif_type = binding.vif_type
            self._original_vif_details = self._plugin._get_vif_details(binding)
            self._original_binding_levels = self._binding_levels
        else:
            self._original_vif_type = None
            self._original_vif_details = None
            self._original_binding_levels = None
        self._new_port_status = None

    # The following methods are for use by the ML2 plugin and are not
    # part of the driver API.

    def _prepare_to_bind(self, segments_to_bind):
        self._segments_to_bind = segments_to_bind
        self._new_bound_segment = None
        self._next_segments_to_bind = None

    def _clear_binding_levels(self):
        self._binding_levels = []

    def _push_binding_level(self, binding_level):
        # NOTE(slaweq): binding_level should be always OVO with no reference
        # to DB object
        self._binding_levels.append(binding_level)

    def _pop_binding_level(self):
        return self._binding_levels.pop()

    # The following implement the abstract methods and properties of
    # the driver API.

    @property
    def current(self):
        return self._port

    @property
    def original(self):
        return self._original_port

    @property
    def status(self):
        # REVISIT(rkukura): Eliminate special DVR case as part of
        # resolving bug 1367391?
        if self._port['device_owner'] == constants.DEVICE_OWNER_DVR_INTERFACE:
            return self._binding.status

        return self._port['status']

    @property
    def original_status(self):
        # REVISIT(rkukura): Should return host-specific status for DVR
        # ports. Fix as part of resolving bug 1367391.
        if self._original_port:
            return self._original_port['status']

    @property
    def network(self):
        if not self._network_context:
            network = self._plugin.get_network(
                self._plugin_context, self.current['network_id'])
            self._network_context = NetworkContext(
                self._plugin, self._plugin_context, network)
        return self._network_context

    @property
    def binding_levels(self):
        if self._binding_levels:
            return [{
                api.BOUND_DRIVER: level.driver,
                api.BOUND_SEGMENT: self._expand_segment(level.segment_id)
            } for level in self._binding_levels]

    @property
    def original_binding_levels(self):
        if self._original_binding_levels:
            return [{
                api.BOUND_DRIVER: level.driver,
                api.BOUND_SEGMENT: self._expand_segment(level.segment_id)
            } for level in self._original_binding_levels]

    @property
    def top_bound_segment(self):
        if self._binding_levels:
            return self._expand_segment(self._binding_levels[0].segment_id)

    @property
    def original_top_bound_segment(self):
        if self._original_binding_levels:
            return self._expand_segment(
                self._original_binding_levels[0].segment_id)

    @property
    def bottom_bound_segment(self):
        if self._binding_levels:
            return self._expand_segment(self._binding_levels[-1].segment_id)

    @property
    def original_bottom_bound_segment(self):
        if self._original_binding_levels:
            return self._expand_segment(
                self._original_binding_levels[-1].segment_id)

    def _expand_segment(self, segment_id):
        for s in self.network.network_segments:
            if s['id'] == segment_id:
                return s
        # TODO(kevinbenton): eliminate the query below. The above should
        # always return since the port is bound to a network segment. Leaving
        # in for now for minimally invasive change for back-port.
        segment = segments_db.get_segment_by_id(self._plugin_context,
                                                segment_id)
        if not segment:
            LOG.warning("Could not expand segment %s", segment_id)
        return segment

    @property
    def host(self):
        # REVISIT(rkukura): Eliminate special DVR case as part of
        # resolving bug 1367391?
        if self._port['device_owner'] == constants.DEVICE_OWNER_DVR_INTERFACE:
            return self._binding.host

        return self._port.get(portbindings.HOST_ID)

    @property
    def original_host(self):
        # REVISIT(rkukura): Eliminate special DVR case as part of
        # resolving bug 1367391?
        if self._port['device_owner'] == constants.DEVICE_OWNER_DVR_INTERFACE:
            return self._original_port and self._binding.host
        else:
            return (self._original_port and
                    self._original_port.get(portbindings.HOST_ID))

    @property
    def vif_type(self):
        return self._binding.vif_type

    @property
    def original_vif_type(self):
        return self._original_vif_type

    @property
    def vif_details(self):
        return self._plugin._get_vif_details(self._binding)

    @property
    def original_vif_details(self):
        return self._original_vif_details

    @property
    def segments_to_bind(self):
        return self._segments_to_bind

    def host_agents(self, agent_type):
        return self._plugin.get_agents(self._plugin_context,
                                       filters={'agent_type': [agent_type],
                                                'host': [self._binding.host]})

    def set_binding(self, segment_id, vif_type, vif_details,
                    status=None):
        # TODO(rkukura) Verify binding allowed, segment in network
        self._new_bound_segment = segment_id
        self._binding.vif_type = vif_type
        self._binding.vif_details = jsonutils.dumps(vif_details)
        self._new_port_status = status

    def _unset_binding(self):
        '''Undo a previous call to set_binding() before it gets committed.

        This method is for MechanismManager and is not part of the driver API.
        '''
        self._new_bound_segment = None
        self._binding.vif_type = portbindings.VIF_TYPE_UNBOUND
        self._binding.vif_details = ''
        self._new_port_status = None

    def continue_binding(self, segment_id, next_segments_to_bind):
        # TODO(rkukura) Verify binding allowed, segment in network
        self._new_bound_segment = segment_id
        self._next_segments_to_bind = next_segments_to_bind

    def allocate_dynamic_segment(self, segment):
        network_id = self._network_context.current['id']

        return self._plugin.type_manager.allocate_dynamic_segment(
                self._plugin_context, network_id, segment)

    def release_dynamic_segment(self, segment_id):
        return self._plugin.type_manager.release_dynamic_segment(
                self._plugin_context, segment_id)
