# Copyright (c) 2016 IBM Corp.
#
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

import abc


class NetworkSegment(object):
    """Represents a Neutron network segment"""
    def __init__(self, network_type, physical_network, segmentation_id,
                 mtu=None):
        self.network_type = network_type
        self.physical_network = physical_network
        self.segmentation_id = segmentation_id
        self.mtu = mtu


class CommonAgentManagerRpcCallBackBase(object, metaclass=abc.ABCMeta):
    """Base class for managers RPC callbacks.

    This class must be inherited by a RPC callback class that is used
    in combination with the common agent.
    """
    def __init__(self, context, agent, sg_agent):
        self.context = context
        self.agent = agent
        self.sg_agent = sg_agent
        self.network_map = {}
        # stores received port_updates and port_deletes for
        # processing by the main loop
        self.updated_devices = set()

    @abc.abstractmethod
    def security_groups_rule_updated(self, context, **kwargs):
        """Callback for security group rule update.

        :param security_groups: list of updated security_groups
        """

    @abc.abstractmethod
    def security_groups_member_updated(self, context, **kwargs):
        """Callback for security group member update.

        :param security_groups: list of updated security_groups
        """

    def add_network(self, network_id, network_segment):
        """Add a network to the agent internal network list

        :param network_id: The UUID of the network
        :param network_segment: The NetworkSegment object for this network
        """
        self.network_map[network_id] = network_segment

    def get_and_clear_updated_devices(self):
        """Get and clear the list of devices for which a update was received.

        :return: set - A set with updated devices. Format is ['tap1', 'tap2']
        """

        # Save and reinitialize the set variable that the port_update RPC uses.
        # This should be thread-safe as the greenthread should not yield
        # between these two statements.
        updated_devices = self.updated_devices
        self.updated_devices = set()
        return updated_devices


class CommonAgentManagerBase(object, metaclass=abc.ABCMeta):
    """Base class for managers that are used with the common agent loop.

    This class must be inherited by a manager class that is used
    in combination with the common agent.
    """

    @abc.abstractmethod
    def ensure_port_admin_state(self, device, admin_state_up):
        """Enforce admin_state for a port

        :param device: The device for which the admin_state should be set
        :param admin_state_up: True for admin_state_up, False for
            admin_state_down
        """

    @abc.abstractmethod
    def get_agent_configurations(self):
        """Establishes the agent configuration map.

        The content of this map is part of the agent state reports to the
        neutron server.

        :return: map -- the map containing the configuration values
        :rtype: dict
        """

    @abc.abstractmethod
    def get_agent_id(self):
        """Calculate the agent id that should be used on this host

        :return: str -- agent identifier
        """

    @abc.abstractmethod
    def get_all_devices(self):
        """Get a list of all devices of the managed type from this host

        A device in this context is a String that represents a network device.
        This can for example be the name of the device or its MAC address.
        This value will be stored in the Plug-in and be part of the
        device_details.

        Typically this list is retrieved from the sysfs. E.g. for linuxbridge
        it returns all names of devices of type 'tap' that start with a certain
        prefix.

        :return: set -- the set of all devices e.g. ['tap1', 'tap2']
        """

    @abc.abstractmethod
    def get_devices_modified_timestamps(self, devices):
        """Get a dictionary of modified timestamps by device

        The devices passed in are expected to be the same format that
        get_all_devices returns.

        :return: dict -- A dictionary of timestamps keyed by device
        """

    @abc.abstractmethod
    def get_extension_driver_type(self):
        """Get the agent extension driver type.

        :return: str -- The String defining the agent extension type
        """

    @abc.abstractmethod
    def get_rpc_callbacks(self, context, agent, sg_agent):
        """Returns the class containing all the agent rpc callback methods

        :return: class - the class containing the agent rpc callback methods.
            It must reflect the CommonAgentManagerRpcCallBackBase Interface.
        """

    @abc.abstractmethod
    def get_agent_api(self, **kwargs):
        """Get L2 extensions drivers API interface class.

        :return: instance of the class containing Agent Extension API
        """

    @abc.abstractmethod
    def get_rpc_consumers(self):
        """Get a list of topics for which an RPC consumer should be created

        :return: list -- A list of topics. Each topic in this list is a list
            consisting of a name, an operation, and an optional host param
            keying the subscription to topic.host for plugin calls.
        """

    @abc.abstractmethod
    def plug_interface(self, network_id, network_segment, device,
                       device_owner):
        """Plug the interface (device).

        :param network_id: The UUID of the Neutron network
        :param network_segment: The NetworkSegment object for this network
        :param device: The device that should be plugged
        :param device_owner: The device owner of the port
        :return: bool -- True if the interface is plugged now. False if the
            interface could not be plugged.
        """

    @abc.abstractmethod
    def setup_arp_spoofing_protection(self, device, device_details):
        """Setup the arp spoofing protection for the given port.

        :param device: The device to set up arp spoofing rules for, where
            device is the device String that is stored in the Neutron Plug-in
            for this Port. E.g. 'tap1'
        :param device_details: The device_details map retrieved from the
            Neutron Plugin
        """

    @abc.abstractmethod
    def delete_arp_spoofing_protection(self, devices):
        """Remove the arp spoofing protection for the given ports.

        :param devices: List of devices that have been removed, where device
            is the device String that is stored for this port in the Neutron
            Plug-in. E.g. ['tap1', 'tap2']
        """

    @abc.abstractmethod
    def delete_unreferenced_arp_protection(self, current_devices):
        """Cleanup arp spoofing protection entries.

        :param current_devices: List of devices that currently exist on this
            host, where device is the device String that could have been stored
            in the Neutron Plug-in. E.g. ['tap1', 'tap2']
        """
