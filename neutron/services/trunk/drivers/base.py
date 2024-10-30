# Copyright 2016 Hewlett Packard Enterprise Development Company, LP
#
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import abc

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources


@registry.has_registry_receivers
class DriverBase:

    def __init__(self, name, interfaces, segmentation_types,
                 agent_type=None, can_trunk_bound_port=False):
        """Instantiate a trunk driver.

        :param name: driver name.
        :param interfaces: list of interfaces supported.
        :param segmentation_types: list of segmentation types supported.
        :param agent_type: agent type for the driver, None if agentless.
        :param can_trunk_bound_port: True if trunk creation is allowed
         for a bound parent port (i.e. trunk creation after VM boot).
        """

        self.name = name
        self.interfaces = interfaces
        self.segmentation_types = segmentation_types
        self.agent_type = agent_type
        self.can_trunk_bound_port = can_trunk_bound_port

    @property
    @abc.abstractmethod
    def is_loaded(self):
        """True if the driver is active for the Neutron Server.

        Implement this property to determine if your driver is actively
        configured for this Neutron Server deployment, e.g. check if
        core_plugin or mech_drivers config options (for ML2) is set as
        required.
        """

    def is_interface_compatible(self, interface):
        """True if the driver is compatible with the interface."""
        return interface in self.interfaces

    def is_agent_compatible(self, agent_type):
        """True if the driver is compatible with the agent type."""
        return agent_type == self.agent_type

    @registry.receives(resources.TRUNK_PLUGIN, [events.AFTER_INIT])
    def register(self, resource, event, trigger, payload=None):
        """Register the trunk driver.

        This method should be overridden so that the driver can subscribe
        to the required trunk events. The driver should also advertise
        itself as supported driver by calling register_driver() on the
        TrunkPlugin otherwise the trunk plugin may fail to start if no
        compatible configuration is found.

        External drivers must subscribe to the AFTER_INIT event for the
        trunk plugin so that they can integrate without an explicit
        register() method invocation.

        :param resource: neutron_lib.callbacks.resources.TRUNK_PLUGIN
        :param event: neutron_lib.callbacks.events.AFTER_INIT
        :param trigger: neutron.service.trunks.plugin.TrunkPlugin
        """

        trigger.register_driver(self)

    @property
    def rpc_required(self):
        """True if this driver requires the RPC backend to be started"""
        return self.is_loaded and self.agent_type
