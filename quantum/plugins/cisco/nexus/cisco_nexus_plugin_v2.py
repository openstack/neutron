# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 Cisco Systems, Inc.  All rights reserved.
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
# @author: Edgar Magana, Cisco Systems, Inc.
#
"""
PlugIn for Nexus OS driver
"""
import logging

from quantum.common import exceptions as exc
from quantum.db import api as db
from quantum.openstack.common import importutils
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.common import cisco_credentials_v2 as cred
from quantum.plugins.cisco.common import cisco_exceptions as excep
from quantum.plugins.cisco.db import network_db_v2 as cdb
from quantum.plugins.cisco.db import nexus_db_v2 as nxos_db
from quantum.plugins.cisco.l2device_plugin_base import L2DevicePluginBase
from quantum.plugins.cisco.nexus import cisco_nexus_configuration as conf


LOG = logging.getLogger(__name__)


class NexusPlugin(L2DevicePluginBase):
    """
    Nexus PLugIn Main Class
    """
    _networks = {}

    def __init__(self):
        """
        Extracts the configuration parameters from the configuration file
        """
        self._client = importutils.import_object(conf.NEXUS_DRIVER)
        LOG.debug("Loaded driver %s\n" % conf.NEXUS_DRIVER)
        self._nexus_ip = conf.NEXUS_IP_ADDRESS
        self._nexus_username = cred.Store.get_username(conf.NEXUS_IP_ADDRESS)
        self._nexus_password = cred.Store.get_password(conf.NEXUS_IP_ADDRESS)
        self._nexus_ports = conf.NEXUS_PORTS
        self._nexus_ssh_port = conf.NEXUS_SSH_PORT

    def get_all_networks(self, tenant_id):
        """
        Returns a dictionary containing all
        <network_uuid, network_name> for
        the specified tenant.
        """
        LOG.debug("NexusPlugin:get_all_networks() called\n")
        return self._networks.values()

    def create_network(self, tenant_id, net_name, net_id, vlan_name, vlan_id,
                       **kwargs):
        """
        Create a VLAN in the switch, and configure the appropriate interfaces
        for this VLAN
        """
        LOG.debug("NexusPlugin:create_network() called\n")
        vlan_ids = ''
        for key in kwargs:
            if key == 'vlan_ids':
                vlan_ids = kwargs['vlan_ids']
        self._client.create_vlan(
            vlan_name, str(vlan_id), self._nexus_ip,
            self._nexus_username, self._nexus_password,
            self._nexus_ports, self._nexus_ssh_port, vlan_ids)
        for ports in self._nexus_ports:
            try:
                nxos_db.add_nexusport_binding(ports, str(vlan_id))
            except:
                raise excep.NexusPortBindingAlreadyExists(port_id=ports)

        new_net_dict = {const.NET_ID: net_id,
                        const.NET_NAME: net_name,
                        const.NET_PORTS: {},
                        const.NET_VLAN_NAME: vlan_name,
                        const.NET_VLAN_ID: vlan_id}
        self._networks[net_id] = new_net_dict
        return new_net_dict

    def delete_network(self, tenant_id, net_id, **kwargs):
        """
        Deletes a VLAN in the switch, and removes the VLAN configuration
        from the relevant interfaces
        """
        LOG.debug("NexusPlugin:delete_network() called\n")
        vlan_id = None
        for key in kwargs:
            if key == const.CONTEXT:
                context = kwargs[const.CONTEXT]
            elif key == const.BASE_PLUGIN_REF:
                base_plugin_ref = kwargs[const.BASE_PLUGIN_REF]
            elif key == 'vlan_id':
                vlan_id = kwargs['vlan_id']
        if vlan_id is None:
            vlan_id = self._get_vlan_id_for_network(tenant_id, net_id,
                                                    context, base_plugin_ref)
        ports_id = nxos_db.get_nexusport_binding(vlan_id)
        LOG.debug("NexusPlugin: Interfaces to be disassociated: %s" % ports_id)
        nxos_db.remove_nexusport_binding(vlan_id)
        if net_id:
            self._client.delete_vlan(
                str(vlan_id), self._nexus_ip,
                self._nexus_username, self._nexus_password,
                self._nexus_ports, self._nexus_ssh_port)
            return net_id
        # Network not found
        raise exc.NetworkNotFound(net_id=net_id)

    def get_network_details(self, tenant_id, net_id, **kwargs):
        """
        Returns the details of a particular network
        """
        LOG.debug("NexusPlugin:get_network_details() called\n")
        network = self._get_network(tenant_id, net_id)
        return network

    def update_network(self, tenant_id, net_id, **kwargs):
        """
        Updates the properties of a particular
        Virtual Network.
        """
        LOG.debug("NexusPlugin:update_network() called\n")
        if 'net_admin_state' in kwargs:
            net_admin_state = kwargs['net_admin_state']
            vlan_id = kwargs['vlan_id']
            vlan_ids = kwargs['vlan_ids']
            if not net_admin_state:
                self._client.remove_vlan_int(
                    str(vlan_id), self._nexus_ip,
                    self._nexus_username, self._nexus_password,
                    self._nexus_ports, self._nexus_ssh_port)
            else:
                self._client.add_vlan_int(
                    str(vlan_id), self._nexus_ip,
                    self._nexus_username, self._nexus_password,
                    self._nexus_ports, self._nexus_ssh_port,
                    vlan_ids)
        return net_id

    def get_all_ports(self, tenant_id, net_id, **kwargs):
        """
        This is probably not applicable to the Nexus plugin.
        Delete if not required.
        """
        LOG.debug("NexusPlugin:get_all_ports() called\n")

    def create_port(self, tenant_id, net_id, port_state, port_id, **kwargs):
        """
        This is probably not applicable to the Nexus plugin.
        Delete if not required.
        """
        LOG.debug("NexusPlugin:create_port() called\n")

    def delete_port(self, tenant_id, net_id, port_id, **kwargs):
        """
        This is probably not applicable to the Nexus plugin.
        Delete if not required.
        """
        LOG.debug("NexusPlugin:delete_port() called\n")

    def update_port(self, tenant_id, net_id, port_id, port_state, **kwargs):
        """
        This is probably not applicable to the Nexus plugin.
        Delete if not required.
        """
        LOG.debug("NexusPlugin:update_port() called\n")

    def get_port_details(self, tenant_id, net_id, port_id, **kwargs):
        """
        This is probably not applicable to the Nexus plugin.
        Delete if not required.
        """
        LOG.debug("NexusPlugin:get_port_details() called\n")

    def plug_interface(self, tenant_id, net_id, port_id, remote_interface_id,
                       **kwargs):
        """
        This is probably not applicable to the Nexus plugin.
        Delete if not required.
        """
        LOG.debug("NexusPlugin:plug_interface() called\n")

    def unplug_interface(self, tenant_id, net_id, port_id, **kwargs):
        """
        This is probably not applicable to the Nexus plugin.
        Delete if not required.
        """
        LOG.debug("NexusPlugin:unplug_interface() called\n")

    def _get_vlan_id_for_network(self, tenant_id, network_id, context,
                                 base_plugin_ref):
        """
        Obtain the VLAN ID given the Network ID
        """
        vlan = cdb.get_vlan_binding(network_id)
        return vlan.vlan_id

    def _get_network(self, tenant_id, network_id, context, base_plugin_ref):
        """
        Gets the NETWORK ID
        """
        network = base_plugin_ref._get_network(context, network_id)
        if not network:
            raise exc.NetworkNotFound(net_id=network_id)
        return {const.NET_ID: network_id, const.NET_NAME: network.name,
                const.NET_PORTS: network.ports}
