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
from quantum.common import utils
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.common import cisco_credentials as cred
from quantum.plugins.cisco.common import cisco_exceptions as cexc
from quantum.plugins.cisco.common import cisco_utils as cutil
from quantum.plugins.cisco.l2device_plugin_base import L2DevicePluginBase
from quantum.plugins.cisco.ucs import cisco_ucs_configuration as conf

LOG.basicConfig(level=LOG.WARN)
LOG.getLogger(const.LOGGER_COMPONENT_NAME)


class UCSVICPlugin(L2DevicePluginBase):
    _networks = {}

    def __init__(self):
        self._client = utils.import_object(conf.UCSM_DRIVER)
        LOG.debug("Loaded driver %s\n" % conf.UCSM_DRIVER)
        self._utils = cutil.DBUtils()
        # TODO (Sumit) This is for now, when using only one chassis
        self._ucsm_ip = conf.UCSM_IP_ADDRESS
        self._ucsm_username = cred.Store.getUsername(conf.UCSM_IP_ADDRESS)
        self._ucsm_password = cred.Store.getPassword(conf.UCSM_IP_ADDRESS)
        # TODO (Sumit) Make the counter per UCSM
        self._port_profile_counter = 0

    def get_all_networks(self, tenant_id, **kwargs):
        """
        Returns a dictionary containing all
        <network_uuid, network_name> for
        the specified tenant.
        """
        LOG.debug("UCSVICPlugin:get_all_networks() called\n")
        return self._networks.values()

    def create_network(self, tenant_id, net_name, net_id, vlan_name, vlan_id,
                       **kwargs):
        """
        Creates a new Virtual Network, and assigns it
        a symbolic name.
        """
        LOG.debug("UCSVICPlugin:create_network() called\n")
        self._client.create_vlan(vlan_name, str(vlan_id), self._ucsm_ip,
                                 self._ucsm_username, self._ucsm_password)
        new_net_dict = {const.NET_ID: net_id,
                        const.NET_NAME: net_name,
                        const.NET_PORTS: {},
                        const.NET_VLAN_NAME: vlan_name,
                        const.NET_VLAN_ID: vlan_id}
        self._networks[net_id] = new_net_dict
        return new_net_dict

    def delete_network(self, tenant_id, net_id, **kwargs):
        """
        Deletes the network with the specified network identifier
        belonging to the specified tenant.
        """
        LOG.debug("UCSVICPlugin:delete_network() called\n")
        net = self._networks.get(net_id)
        # TODO (Sumit) : Verify that no attachments are plugged into the
        # network
        if net:
            # TODO (Sumit) : Before deleting the network, make sure all the
            # ports associated with this network are also deleted
            self._client.delete_vlan(net[const.NET_VLAN_NAME], self._ucsm_ip,
                                     self._ucsm_username, self._ucsm_password)
            self._networks.pop(net_id)
            return net
        raise exc.NetworkNotFound(net_id=net_id)

    def get_network_details(self, tenant_id, net_id, **kwargs):
        """
        Deletes the Virtual Network belonging to a the
        spec
        """
        LOG.debug("UCSVICPlugin:get_network_details() called\n")
        network = self._get_network(tenant_id, net_id)
        return network

    def rename_network(self, tenant_id, net_id, new_name, **kwargs):
        """
        Updates the symbolic name belonging to a particular
        Virtual Network.
        """
        LOG.debug("UCSVICPlugin:rename_network() called\n")
        network = self._get_network(tenant_id, net_id)
        network[const.NET_NAME] = new_name
        return network

    def get_all_ports(self, tenant_id, net_id, **kwargs):
        """
        Retrieves all port identifiers belonging to the
        specified Virtual Network.
        """
        LOG.debug("UCSVICPlugin:get_all_ports() called\n")
        network = self._get_network(tenant_id, net_id)
        ports_on_net = network[const.NET_PORTS].values()
        return ports_on_net

    def create_port(self, tenant_id, net_id, port_state, port_id, **kwargs):
        """
        Creates a port on the specified Virtual Network.
        """
        LOG.debug("UCSVICPlugin:create_port() called\n")
        net = self._get_network(tenant_id, net_id)
        ports = net[const.NET_PORTS]
        # TODO (Sumit): This works on a single host deployment,
        # in multi-host environment, dummy needs to be replaced with the
        # hostname
        dynamic_nic_name = self._client.get_dynamic_nic("dummy")
        new_port_profile = self._create_port_profile(tenant_id, net_id,
                                                     port_id,
                                                     conf.DEFAULT_VLAN_NAME,
                                                     conf.DEFAULT_VLAN_ID)
        profile_name = new_port_profile[const.PROFILE_NAME]
        sql_query = "INSERT INTO ports (port_id, profile_name, dynamic_vnic," \
        "host, instance_name, instance_nic_name, used) VALUES" \
        "('%s', '%s', '%s', 'dummy', NULL, NULL, 0)" % \
        (port_id, profile_name, dynamic_nic_name)
        self._utils.execute_db_query(sql_query)
        new_port_dict = {const.PORT_ID: port_id,
                         const.PORT_STATE: const.PORT_UP,
                         const.ATTACHMENT: None,
                         const.PORT_PROFILE: new_port_profile}
        ports[port_id] = new_port_dict
        return new_port_dict

    def delete_port(self, tenant_id, net_id, port_id, **kwargs):
        """
        Deletes a port on a specified Virtual Network,
        if the port contains a remote interface attachment,
        the remote interface should first be un-plugged and
        then the port can be deleted.
        """
        LOG.debug("UCSVICPlugin:delete_port() called\n")
        port = self._get_port(tenant_id, net_id, port_id)
        if port[const.ATTACHMENT]:
            raise exc.PortInUse(net_id=net_id, port_id=port_id,
                                att_id=port[const.ATTACHMENT])
        try:
            #TODO (Sumit): Before deleting port profile make sure that there
            # is no VM using this port profile
            self._client.release_dynamic_nic("dummy")
            port_profile = port[const.PORT_PROFILE]
            self._delete_port_profile(port_id,
                                      port_profile[const.PROFILE_NAME])
            sql_query = "delete from ports where port_id = \"%s\"" % \
            (port[const.PORT_ID])
            self._utils.execute_db_query(sql_query)
            net = self._get_network(tenant_id, net_id)
            net[const.NET_PORTS].pop(port_id)
        except KeyError:
            raise exc.PortNotFound(net_id=net_id, port_id=port_id)

    def update_port(self, tenant_id, net_id, port_id, port_state, **kwargs):
        """
        Updates the state of a port on the specified Virtual Network.
        """
        LOG.debug("UCSVICPlugin:update_port() called\n")
        port = self._get_port(tenant_id, net_id, port_id)
        self._validate_port_state(port_state)
        port[const.PORT_STATE] = port_state
        return port

    def get_port_details(self, tenant_id, net_id, port_id, **kwargs):
        """
        This method allows the user to retrieve a remote interface
        that is attached to this particular port.
        """
        LOG.debug("UCSVICPlugin:get_port_details() called\n")
        return self._get_port(tenant_id, net_id, port_id)

    def plug_interface(self, tenant_id, net_id, port_id, remote_interface_id,
                       **kwargs):
        """
        Attaches a remote interface to the specified port on the
        specified Virtual Network.
        """
        LOG.debug("UCSVICPlugin:plug_interface() called\n")
        self._validate_attachment(tenant_id, net_id, port_id,
                                  remote_interface_id)
        port = self._get_port(tenant_id, net_id, port_id)
        if port[const.ATTACHMENT]:
            raise exc.PortInUse(net_id=net_id, port_id=port_id,
                                att_id=port[const.ATTACHMENT])
        port[const.ATTACHMENT] = remote_interface_id
        port_profile = port[const.PORT_PROFILE]
        profile_name = port_profile[const.PROFILE_NAME]
        old_vlan_name = port_profile[const.PROFILE_VLAN_NAME]
        new_vlan_name = self._get_vlan_name_for_network(tenant_id, net_id)
        new_vlan_id = self._get_vlan_id_for_network(tenant_id, net_id)
        self._client.change_vlan_in_profile(profile_name, old_vlan_name,
                                            new_vlan_name, self._ucsm_ip,
                                            self._ucsm_username,
                                            self._ucsm_password)
        port_profile[const.PROFILE_VLAN_NAME] = new_vlan_name
        port_profile[const.PROFILE_VLAN_ID] = new_vlan_id

    def unplug_interface(self, tenant_id, net_id, port_id, **kwargs):
        """
        Detaches a remote interface from the specified port on the
        specified Virtual Network.
        """
        LOG.debug("UCSVICPlugin:unplug_interface() called\n")
        port = self._get_port(tenant_id, net_id, port_id)
        port[const.ATTACHMENT] = None
        port_profile = port[const.PORT_PROFILE]
        profile_name = port_profile[const.PROFILE_NAME]
        old_vlan_name = port_profile[const.PROFILE_VLAN_NAME]
        new_vlan_name = conf.DEFAULT_VLAN_NAME
        self._client.change_vlan_in_profile(profile_name, old_vlan_name,
                                            new_vlan_name, self._ucsm_ip,
                                            self._ucsm_username,
                                            self._ucsm_password)
        port_profile[const.PROFILE_VLAN_NAME] = conf.DEFAULT_VLAN_NAME
        port_profile[const.PROFILE_VLAN_ID] = conf.DEFAULT_VLAN_ID

    def _get_profile_name(self, port_id):
        profile_name = conf.PROFILE_NAME_PREFIX + port_id
        return profile_name

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

    def _get_vlan_name_for_network(self, tenant_id, network_id):
        net = self._get_network(tenant_id, network_id)
        vlan_name = net[const.NET_VLAN_NAME]
        return vlan_name

    def _get_vlan_id_for_network(self, tenant_id, network_id):
        net = self._get_network(tenant_id, network_id)
        vlan_id = net[const.NET_VLAN_ID]
        return vlan_id

    def _get_port(self, tenant_id, network_id, port_id):
        net = self._get_network(tenant_id, network_id)
        port = net[const.NET_PORTS].get(port_id)
        if not port:
            raise exc.PortNotFound(net_id=network_id, port_id=port_id)
        return port

    def _create_port_profile(self, tenant_id, net_id, port_id, vlan_name,
                             vlan_id):
        if self._port_profile_counter >= int(conf.MAX_UCSM_PORT_PROFILES):
            raise cexc.UCSMPortProfileLimit(net_id=net_id, port_id=port_id)
        profile_name = self._get_profile_name(port_id)
        self._client.create_profile(profile_name, vlan_name, self._ucsm_ip,
                                    self._ucsm_username, self._ucsm_password)
        self._port_profile_counter += 1
        new_port_profile = {const.PROFILE_NAME: profile_name,
                            const.PROFILE_VLAN_NAME: vlan_name,
                            const.PROFILE_VLAN_ID: vlan_id}
        return new_port_profile

    def _delete_port_profile(self, port_id, profile_name):
        self._client.delete_profile(profile_name, self._ucsm_ip,
                                    self._ucsm_username, self._ucsm_password)
        self._port_profile_counter -= 1
