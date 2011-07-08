# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2011 Cisco Systems, Inc.  All rights reserved.
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
#
# @author: Sumit Naiksatam, Cisco Systems, Inc.
#
import logging as LOG

from quantum.common import exceptions as exc
from quantum.plugins.cisco import cisco_configuration as conf
from quantum.plugins.cisco import cisco_constants as const
from quantum.plugins.cisco import cisco_credentials as cred
from quantum.plugins.cisco import cisco_exceptions as cexc
from quantum.plugins.cisco import cisco_utils as cutil

LOG.basicConfig(level=LOG.WARN)
LOG.getLogger(const.LOGGER_COMPONENT_NAME)


class NexusPlugin(object):
    _networks = {}

    def __init__(self):
        """
        Initialize the Nexus driver here
        """
        pass

    def get_all_networks(self, tenant_id):
        """
        Returns a dictionary containing all
        <network_uuid, network_name> for
        the specified tenant.
        """
        LOG.debug("NexusPlugin:get_all_networks() called\n")
        return self._networks.values()

    def create_network(self, tenant_id, net_name, net_id, vlan_name, vlan_id):
        """
        Create a VLAN in the switch, and configure the appropriate interfaces
        for this VLAN
        """
        LOG.debug("NexusPlugin:create_network() called\n")
        # TODO (Sumit): Call the nexus driver here to create the VLAN, and
        # configure the appropriate interfaces
        new_net_dict = {const.NET_ID: net_id,
                        const.NET_NAME: net_name,
                        const.NET_PORTS: {},
                        const.NET_VLAN_NAME: vlan_name,
                        const.NET_VLAN_ID: vlan_id}
        self._networks[net_id] = new_net_dict
        return new_net_dict

    def delete_network(self, tenant_id, net_id):
        """
        Deletes a VLAN in the switch, and removes the VLAN configuration
        from the relevant interfaces
        """
        LOG.debug("NexusPlugin:delete_network() called\n")
        net = self._networks.get(net_id)
        if net:
            # TODO (Sumit): Call the nexus driver here to create the VLAN,
            # and configure the appropriate interfaces
            self._networks.pop(net_id)
            return net
        # Network not found
        raise exc.NetworkNotFound(net_id=net_id)

    def get_network_details(self, tenant_id, net_id):
        """
        Returns the details of a particular network
        """
        LOG.debug("NexusPlugin:get_network_details() called\n")
        network = self._get_network(tenant_id, net_id)
        return network

    def rename_network(self, tenant_id, net_id, new_name):
        """
        Updates the symbolic name belonging to a particular
        Virtual Network.
        """
        LOG.debug("NexusPlugin:rename_network() called\n")
        network = self._get_network(tenant_id, net_id)
        network[const.NET_NAME] = new_name
        return network

    def get_all_ports(self, tenant_id, net_id):
        """
        This is probably not applicable to the Nexus plugin.
        Delete if not required.
        """
        LOG.debug("NexusPlugin:get_all_ports() called\n")

    def create_port(self, tenant_id, net_id, port_state, port_id):
        """
        This is probably not applicable to the Nexus plugin.
        Delete if not required.
        """
        LOG.debug("NexusPlugin:create_port() called\n")

    def delete_port(self, tenant_id, net_id, port_id):
        """
        This is probably not applicable to the Nexus plugin.
        Delete if not required.
        """
        LOG.debug("NexusPlugin:delete_port() called\n")

    def update_port(self, tenant_id, net_id, port_id, port_state):
        """
        This is probably not applicable to the Nexus plugin.
        Delete if not required.
        """
        LOG.debug("NexusPlugin:update_port() called\n")

    def get_port_details(self, tenant_id, net_id, port_id):
        """
        This is probably not applicable to the Nexus plugin.
        Delete if not required.
        """
        LOG.debug("NexusPlugin:get_port_details() called\n")

    def plug_interface(self, tenant_id, net_id, port_id, remote_interface_id):
        """
        This is probably not applicable to the Nexus plugin.
        Delete if not required.
        """
        LOG.debug("NexusPlugin:plug_interface() called\n")

    def unplug_interface(self, tenant_id, net_id, port_id):
        """
        This is probably not applicable to the Nexus plugin.
        Delete if not required.
        """
        LOG.debug("NexusPlugin:unplug_interface() called\n")

    def _get_network(self, tenant_id, network_id):
        network = self._networks.get(network_id)
        if not network:
            raise exc.NetworkNotFound(net_id=network_id)
        return network
