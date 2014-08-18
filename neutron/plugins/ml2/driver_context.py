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

from neutron.common import constants
from neutron.extensions import portbindings
from neutron.openstack.common import jsonutils
from neutron.plugins.ml2 import db
from neutron.plugins.ml2 import driver_api as api


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
                 original_network=None):
        super(NetworkContext, self).__init__(plugin, plugin_context)
        self._network = network
        self._original_network = original_network
        self._segments = db.get_network_segments(plugin_context.session,
                                                 network['id'])

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

    def __init__(self, plugin, plugin_context, subnet, original_subnet=None):
        super(SubnetContext, self).__init__(plugin, plugin_context)
        self._subnet = subnet
        self._original_subnet = original_subnet

    @property
    def current(self):
        return self._subnet

    @property
    def original(self):
        return self._original_subnet


class PortContext(MechanismDriverContext, api.PortContext):

    def __init__(self, plugin, plugin_context, port, network, binding,
                 original_port=None):
        super(PortContext, self).__init__(plugin, plugin_context)
        self._port = port
        self._original_port = original_port
        self._network_context = NetworkContext(plugin, plugin_context,
                                               network)
        self._binding = binding
        if original_port:
            self._original_bound_segment_id = self._binding.segment
            self._original_bound_driver = self._binding.driver
        else:
            self._original_bound_segment_id = None
            self._original_bound_driver = None
        self._new_port_status = None

    @property
    def current(self):
        return self._port

    @property
    def original(self):
        return self._original_port

    @property
    def status(self):
        return self._port['status']

    @property
    def original_status(self):
        return self._original_port['status']

    @property
    def network(self):
        return self._network_context

    @property
    def bound_segment(self):
        id = self._binding.segment
        if id:
            for segment in self._network_context.network_segments:
                if segment[api.ID] == id:
                    return segment

    @property
    def original_bound_segment(self):
        if self._original_bound_segment_id:
            for segment in self._network_context.network_segments:
                if segment[api.ID] == self._original_bound_segment_id:
                    return segment

    @property
    def host(self):
        return self._port.get(portbindings.HOST_ID)

    @property
    def original_host(self):
        return self._original_port.get(portbindings.HOST_ID)

    @property
    def bound_driver(self):
        return self._binding.driver

    @property
    def original_bound_driver(self):
        return self._original_bound_driver

    def host_agents(self, agent_type):
        return self._plugin.get_agents(self._plugin_context,
                                       filters={'agent_type': [agent_type],
                                                'host': [self._binding.host]})

    def set_binding(self, segment_id, vif_type, vif_details,
                    status=None):
        # TODO(rkukura) Verify binding allowed, segment in network
        self._binding.segment = segment_id
        self._binding.vif_type = vif_type
        self._binding.vif_details = jsonutils.dumps(vif_details)
        self._new_port_status = status

    def allocate_dynamic_segment(self, segment):
        network_id = self._network_context.current['id']

        return self._plugin.type_manager.allocate_dynamic_segment(
                self._plugin_context.session, network_id, segment)

    def release_dynamic_segment(self, segment_id):
        return self._plugin.type_manager.release_dynamic_segment(
                self._plugin_context.session, segment_id)


class DvrPortContext(PortContext):

    def __init__(self, plugin, plugin_context, port, network, binding,
                 original_port=None):
        super(DvrPortContext, self).__init__(
            plugin, plugin_context, port, network, binding,
            original_port=original_port)

    @property
    def host(self):
        if self._port['device_owner'] == constants.DEVICE_OWNER_DVR_INTERFACE:
            return self._binding.host

        return super(DvrPortContext, self).host

    @property
    def status(self):
        if self._port['device_owner'] == constants.DEVICE_OWNER_DVR_INTERFACE:
            return self._binding.status

        return super(DvrPortContext, self).status
