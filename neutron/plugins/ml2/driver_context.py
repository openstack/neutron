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
                 segments=None, original_network=None):
        super(NetworkContext, self).__init__(plugin, plugin_context)
        self._network = network
        self._original_network = original_network
        self._segments = segments

    def current(self):
        return self._network

    def original(self):
        return self._original_network

    def network_segments(self):
        if not self._segments:
            self._segments = self._plugin.get_network_segments(
                self._plugin_context, self._network['id'])
        return self._segments


class PortContext(MechanismDriverContext, api.PortContext):

    def __init__(self, plugin, plugin_context, port,
                 original_port=None):
        super(PortContext, self).__init__(plugin, plugin_context)
        self._port = port
        self._original_port = original_port
        self._network_context = None

    def current(self):
        return self._port

    def original(self):
        return self._original_port

    def network(self):
        """Return the NetworkContext associated with this port."""
        if not self._network_context:
            network = self._plugin.get_network(self._plugin_context,
                                               self._port["network_id"])
            self._network_context = NetworkContext(self._plugin,
                                                   self._plugin_context,
                                                   network)
        return self._network_context
