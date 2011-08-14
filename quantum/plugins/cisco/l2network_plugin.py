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

import inspect
import logging as LOG

from quantum.common import exceptions as exc
from quantum.common import utils
from quantum.quantum_plugin_base import QuantumPluginBase
from quantum.plugins.cisco import l2network_plugin_configuration as conf
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.common import cisco_exceptions as cexc

LOG.basicConfig(level=LOG.WARN)
LOG.getLogger(const.LOGGER_COMPONENT_NAME)


class L2Network(QuantumPluginBase):
    _networks = {}
    _tenants = {}
    _portprofiles = {}

    def __init__(self):
        self._net_counter = 0
        self._portprofile_counter = 0
        self._port_counter = 0
        self._vlan_counter = int(conf.VLAN_START) - 1
        self._model = utils.import_object(conf.MODEL_CLASS)

    """
    Core API implementation
    """
    def get_all_networks(self, tenant_id):
        """
        Returns a dictionary containing all
        <network_uuid, network_name> for
        the specified tenant.
        """
        LOG.debug("get_all_networks() called\n")
        self._invokeDevicePlugins(self._funcName(), [tenant_id])
        return self._networks.values()

    def create_network(self, tenant_id, net_name):
        """
        Creates a new Virtual Network, and assigns it
        a symbolic name.
        """
        LOG.debug("create_network() called\n")
        new_net_id = self._get_unique_net_id(tenant_id)
        vlan_id = self._get_vlan_for_tenant(tenant_id, net_name)
        vlan_name = self._get_vlan_name(new_net_id, str(vlan_id))
        self._invokeDevicePlugins(self._funcName(), [tenant_id, net_name,
                                                     new_net_id, vlan_name,
                                                     vlan_id])
        new_net_dict = {const.NET_ID: new_net_id,
                        const.NET_NAME: net_name,
                        const.NET_PORTS: {},
                        const.NET_VLAN_NAME: vlan_name,
                        const.NET_VLAN_ID: vlan_id,
                        const.NET_TENANTS: [tenant_id]}
        self._networks[new_net_id] = new_net_dict
        tenant = self._get_tenant(tenant_id)
        tenant_networks = tenant[const.TENANT_NETWORKS]
        tenant_networks[new_net_id] = new_net_dict
        return new_net_dict

    def delete_network(self, tenant_id, net_id):
        """
        Deletes the network with the specified network identifier
        belonging to the specified tenant.
        """
        LOG.debug("delete_network() called\n")
        net = self._networks.get(net_id)
        if net:
            if len(net[const.NET_PORTS].values()) > 0:
                ports_on_net = net[const.NET_PORTS].values()
                for port in ports_on_net:
                    if port[const.ATTACHMENT]:
                        raise exc.NetworkInUse(net_id=net_id)
                for port in ports_on_net:
                    self.delete_port(tenant_id, net_id, port[const.PORT_ID])

            self._invokeDevicePlugins(self._funcName(), [tenant_id, net_id])
            self._networks.pop(net_id)
            tenant = self._get_tenant(tenant_id)
            tenant_networks = tenant[const.TENANT_NETWORKS]
            tenant_networks.pop(net_id)
            return net
        # Network not found
        raise exc.NetworkNotFound(net_id=net_id)

    def get_network_details(self, tenant_id, net_id):
        """
        Gets the details of a particular network
        """
        LOG.debug("get_network_details() called\n")
        self._invokeDevicePlugins(self._funcName(), [tenant_id, net_id])
        network = self._get_network(tenant_id, net_id)
        ports_on_net = network[const.NET_PORTS].values()
        return {const.NET_ID: network[const.NET_ID],
                const.NET_NAME: network[const.NET_NAME],
                const.NET_PORTS: ports_on_net}

    def rename_network(self, tenant_id, net_id, new_name):
        """
        Updates the symbolic name belonging to a particular
        Virtual Network.
        """
        LOG.debug("rename_network() called\n")
        self._invokeDevicePlugins(self._funcName(), [tenant_id, net_id,
                                                     new_name])
        network = self._get_network(tenant_id, net_id)
        network[const.NET_NAME] = new_name
        return network

    def get_all_ports(self, tenant_id, net_id):
        """
        Retrieves all port identifiers belonging to the
        specified Virtual Network.
        """
        LOG.debug("get_all_ports() called\n")
        self._invokeDevicePlugins(self._funcName(), [tenant_id, net_id])
        network = self._get_network(tenant_id, net_id)
        ports_on_net = network[const.NET_PORTS].values()
        return ports_on_net

    def create_port(self, tenant_id, net_id, port_state=None):
        """
        Creates a port on the specified Virtual Network.
        """
        LOG.debug("create_port() called\n")
        net = self._get_network(tenant_id, net_id)
        ports = net[const.NET_PORTS]
        unique_port_id_string = self._get_unique_port_id(tenant_id, net_id)
        self._invokeDevicePlugins(self._funcName(), [tenant_id, net_id,
                                                     port_state,
                                                     unique_port_id_string])
        new_port_dict = {const.PORT_ID: unique_port_id_string,
                         const.PORT_STATE: const.PORT_UP,
                         const.ATTACHMENT: None}
        ports[unique_port_id_string] = new_port_dict
        return new_port_dict

    def delete_port(self, tenant_id, net_id, port_id):
        """
        Deletes a port on a specified Virtual Network,
        if the port contains a remote interface attachment,
        the remote interface should first be un-plugged and
        then the port can be deleted.
        """
        LOG.debug("delete_port() called\n")
        port = self._get_port(tenant_id, net_id, port_id)
        if port[const.ATTACHMENT]:
            raise exc.PortInUse(net_id=net_id, port_id=port_id,
                                att_id=port[const.ATTACHMENT])
        try:
            #TODO (Sumit): Before deleting port profile make sure that there
            # is no VM using this port profile
            self._invokeDevicePlugins(self._funcName(), [tenant_id, net_id,
                                                         port_id])
            net = self._get_network(tenant_id, net_id)
            net[const.NET_PORTS].pop(port_id)
        except KeyError:
            raise exc.PortNotFound(net_id=net_id, port_id=port_id)

    def update_port(self, tenant_id, net_id, port_id, port_state):
        """
        Updates the state of a port on the specified Virtual Network.
        """
        LOG.debug("update_port() called\n")
        self._invokeDevicePlugins(self._funcName(), [tenant_id, net_id,
                                                     port_id, port_state])
        port = self._get_port(tenant_id, net_id, port_id)
        self._validate_port_state(port_state)
        port[const.PORT_STATE] = port_state
        return port

    def get_port_details(self, tenant_id, net_id, port_id):
        """
        This method allows the user to retrieve a remote interface
        that is attached to this particular port.
        """
        LOG.debug("get_port_details() called\n")
        self._invokeDevicePlugins(self._funcName(), [tenant_id, net_id,
                                                     port_id])
        return self._get_port(tenant_id, net_id, port_id)

    def plug_interface(self, tenant_id, net_id, port_id,
                       remote_interface_id):
        """
        Attaches a remote interface to the specified port on the
        specified Virtual Network.
        """
        LOG.debug("plug_interface() called\n")
        self._validate_attachment(tenant_id, net_id, port_id,
                                  remote_interface_id)
        port = self._get_port(tenant_id, net_id, port_id)
        if port[const.ATTACHMENT]:
            raise exc.PortInUse(net_id=net_id, port_id=port_id,
                                att_id=port[const.ATTACHMENT])
        self._invokeDevicePlugins(self._funcName(), [tenant_id, net_id,
                                                     port_id,
                                                     remote_interface_id])
        port[const.ATTACHMENT] = remote_interface_id

    def unplug_interface(self, tenant_id, net_id, port_id):
        """
        Detaches a remote interface from the specified port on the
        specified Virtual Network.
        """
        LOG.debug("unplug_interface() called\n")
        port = self._get_port(tenant_id, net_id, port_id)
        self._invokeDevicePlugins(self._funcName(), [tenant_id, net_id,
                                                     port_id])
        port[const.ATTACHMENT] = None

    """
    Extension API implementation
    """
    def get_all_portprofiles(self, tenant_id):
        return self._portprofiles.values()

    def get_portprofile_details(self, tenant_id, profile_id):
        return self._get_portprofile(tenant_id, profile_id)

    def create_portprofile(self, tenant_id, profile_name, vlan_id):
        profile_id = self._get_unique_profile_id(tenant_id)
        new_port_profile_dict = {const.PROFILE_ID: profile_id,
                                 const.PROFILE_NAME: profile_name,
                                 const.PROFILE_ASSOCIATIONS: [],
                                 const.PROFILE_VLAN_ID: vlan_id,
                                 const.PROFILE_QOS: None}
        self._portprofiles[profile_id] = new_port_profile_dict
        tenant = self._get_tenant(tenant_id)
        portprofiles = tenant[const.TENANT_PORTPROFILES]
        portprofiles[profile_id] = new_port_profile_dict
        return new_port_profile_dict

    def delete_portprofile(self, tenant_id, profile_id):
        portprofile = self._get_portprofile(tenant_id, profile_id)
        associations = portprofile[const.PROFILE_ASSOCIATIONS]
        if len(associations) > 0:
            raise cexc.PortProfileInvalidDelete(tenant_id=tenant_id,
                                               profile_id=profile_id)
        else:
            self._portprofiles.pop(profile_id)
            tenant = self._get_tenant(tenant_id)
            tenant[const.TENANT_PORTPROFILES].pop(profile_id)

    def rename_portprofile(self, tenant_id, profile_id, new_name):
        portprofile = self._get_portprofile(tenant_id, profile_id)
        portprofile[const.PROFILE_NAME] = new_name
        return portprofile

    def associate_portprofile(self, tenant_id, net_id,
                              port_id, portprofile_id):
        portprofile = self._get_portprofile(tenant_id, portprofile_id)
        associations = portprofile[const.PROFILE_ASSOCIATIONS]
        associations.append(port_id)

    def disassociate_portprofile(self, tenant_id, net_id,
                                 port_id, portprofile_id):
        portprofile = self._get_portprofile(tenant_id, portprofile_id)
        associations = portprofile[const.PROFILE_ASSOCIATIONS]
        associations.remove(port_id)

    def create_defaultPProfile(self, tenant_id, network_id, profile_name,
                               vlan_id):
        pass

    """
    Private functions
    """
    def _invokeDevicePlugins(self, function_name, args):
        """
        All device-specific calls are delegate to the model
        """
        getattr(self._model, function_name)(args)

    def _get_vlan_for_tenant(self, tenant_id, net_name):
        # TODO (Sumit):
        # The VLAN ID for a tenant might need to be obtained from
        # somewhere (from Donabe/Melange?)
        # Also need to make sure that the VLAN ID is not being used already
        # Currently, just a wrap-around counter ranging from VLAN_START to
        # VLAN_END
        self._vlan_counter += 1
        self._vlan_counter %= int(conf.VLAN_END)
        if self._vlan_counter < int(conf.VLAN_START):
            self._vlan_counter = int(conf.VLAN_START)
        return self._vlan_counter

    def _get_vlan_name(self, net_id, vlan):
        vlan_name = conf.VLAN_NAME_PREFIX + net_id + "-" + vlan
        return vlan_name

    def _validate_port_state(self, port_state):
        if port_state.upper() not in (const.PORT_UP, const.PORT_DOWN):
            raise exc.StateInvalid(port_state=port_state)
        return True

    def _validate_attachment(self, tenant_id, network_id, port_id,
                             remote_interface_id):
        network = self._get_network(tenant_id, network_id)
        for port in network[const.NET_PORTS].values():
            if port[const.ATTACHMENT] == remote_interface_id:
                raise exc.AlreadyAttached(net_id=network_id,
                                          port_id=port_id,
                                          att_id=port[const.ATTACHMENT],
                                          att_port_id=port[const.PORT_ID])

    def _get_network(self, tenant_id, network_id):
        network = self._networks.get(network_id)
        if not network:
            raise exc.NetworkNotFound(net_id=network_id)
        return network

    def _get_tenant(self, tenant_id):
        tenant = self._tenants.get(tenant_id)
        if not tenant:
            LOG.debug("Creating new tenant record with tenant id %s\n" %
                      tenant_id)
            tenant = {const.TENANT_ID: tenant_id,
                      const.TENANT_NAME: tenant_id,
                      const.TENANT_NETWORKS: {},
                      const.TENANT_PORTPROFILES: {}}
            self._tenants[tenant_id] = tenant
        return tenant

    def _get_port(self, tenant_id, network_id, port_id):
        net = self._get_network(tenant_id, network_id)
        port = net[const.NET_PORTS].get(port_id)
        if not port:
            raise exc.PortNotFound(net_id=network_id, port_id=port_id)
        return port

    def _get_portprofile(self, tenant_id, portprofile_id):
        portprofile = self._portprofiles.get(portprofile_id)
        if not portprofile:
            raise cexc.PortProfileNotFound(tenant_id=tenant_id,
                                           portprofile_id=portprofile_id)
        return portprofile

    def _get_unique_net_id(self, tenant_id):
        self._net_counter += 1
        self._net_counter %= int(conf.MAX_NETWORKS)
        id = tenant_id[:3] + \
        "-n-" + ("0" * (6 - len(str(self._net_counter)))) + \
        str(self._net_counter)
        # TODO (Sumit): Need to check if the ID has already been allocated
        # ID will be generated by DB
        return id

    def _get_unique_port_id(self, tenant_id, net_id):
        self._port_counter += 1
        self._port_counter %= int(conf.MAX_PORTS)
        id = net_id + "-p-" + str(self._port_counter)
        # TODO (Sumit): Need to check if the ID has already been allocated
        # ID will be generated by DB
        return id

    def _get_unique_profile_id(self, tenant_id):
        self._portprofile_counter += 1
        self._portprofile_counter %= int(conf.MAX_PORT_PROFILES)
        id = tenant_id[:3] + "-pp-" + \
                ("0" * (6 - len(str(self._net_counter)))) \
                + str(self._portprofile_counter)
        # TODO (Sumit): Need to check if the ID has already been allocated
        # ID will be generated by DB
        return id

    def _funcName(self, offset=0):
        return inspect.stack()[1 + offset][3]

"""
TODO (Sumit):
(1) Persistent storage
"""
