# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Cisco Systems, Inc.
# All rights reserved.
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
# @author: Arvind Somya, Cisco Systems, Inc. (asomya@cisco.com)
#

"""
PlugIn for Nexus OS driver
"""

import logging

from quantum.common import exceptions as exc
from quantum.openstack.common import importutils
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.common import cisco_credentials_v2 as cred
from quantum.plugins.cisco.common import config as conf
from quantum.plugins.cisco.db import network_db_v2 as cdb
from quantum.plugins.cisco.db import nexus_db_v2 as nxos_db
from quantum.plugins.cisco.l2device_plugin_base import L2DevicePluginBase


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
        self._client = importutils.import_object(conf.CISCO.nexus_driver)
        LOG.debug(_("Loaded driver %s"), conf.CISCO.nexus_driver)
        self._nexus_switches = conf.get_nexus_dictionary()
        self.credentials = {}

    def get_credential(self, nexus_ip):
        if nexus_ip not in self.credentials:
            _nexus_username = cred.Store.get_username(nexus_ip)
            _nexus_password = cred.Store.get_password(nexus_ip)
            self.credentials[nexus_ip] = {
                'username': _nexus_username,
                'password': _nexus_password
            }
        return self.credentials[nexus_ip]

    def get_all_networks(self, tenant_id):
        """
        Returns a dictionary containing all
        <network_uuid, network_name> for
        the specified tenant.
        """
        LOG.debug(_("NexusPlugin:get_all_networks() called"))
        return self._networks.values()

    def create_network(self, tenant_id, net_name, net_id, vlan_name, vlan_id,
                       host, instance):
        """
        Create a VLAN in the appropriate switch/port,
        and configure the appropriate interfaces
        for this VLAN
        """
        LOG.debug(_("NexusPlugin:create_network() called"))
        # Grab the switch IP and port for this host
        switch_ip = ''
        port_id = ''
        for keys in self._nexus_switches.keys():
            if str(keys[1]) == str(host):
                switch_ip = keys[0]
                port_id = self._nexus_switches[keys[0], keys[1]]

        # Check if this network is already in the DB
        binding = nxos_db.get_port_vlan_switch_binding(
            port_id, vlan_id, switch_ip)
        if not binding:
            _nexus_ip = switch_ip
            _nexus_ports = (port_id,)
            _nexus_ssh_port = \
                self._nexus_switches[switch_ip, 'ssh_port']
            _nexus_creds = self.get_credential(_nexus_ip)
            _nexus_username = _nexus_creds['username']
            _nexus_password = _nexus_creds['password']
            # Check for vlan/switch binding
            vbinding = nxos_db.get_nexusvlan_binding(vlan_id, switch_ip)
            if not vbinding:
                # Create vlan and trunk vlan on the port
                self._client.create_vlan(
                    vlan_name, str(vlan_id), _nexus_ip,
                    _nexus_username, _nexus_password,
                    _nexus_ports, _nexus_ssh_port, vlan_id)
            else:
                # Only trunk vlan on the port
                man = self._client.nxos_connect(_nexus_ip,
                                                int(_nexus_ssh_port),
                                                _nexus_username,
                                                _nexus_password)
                self._client.enable_vlan_on_trunk_int(man,
                                                      port_id,
                                                      vlan_id)

        nxos_db.add_nexusport_binding(port_id, str(vlan_id),
                                      switch_ip, instance)
        new_net_dict = {const.NET_ID: net_id,
                        const.NET_NAME: net_name,
                        const.NET_PORTS: {},
                        const.NET_VLAN_NAME: vlan_name,
                        const.NET_VLAN_ID: vlan_id}
        self._networks[net_id] = new_net_dict
        return new_net_dict

    def delete_network(self, tenant_id, net_id, **kwargs):
        """
        Deletes the VLAN in all switches, and removes the VLAN configuration
        from the relevant interfaces
        """
        LOG.debug(_("NexusPlugin:delete_network() called"))

    def get_network_details(self, tenant_id, net_id, **kwargs):
        """
        Returns the details of a particular network
        """
        LOG.debug(_("NexusPlugin:get_network_details() called"))
        network = self._get_network(tenant_id, net_id)
        return network

    def update_network(self, tenant_id, net_id, **kwargs):
        """
        Updates the properties of a particular
        Virtual Network.
        """
        LOG.debug(_("NexusPlugin:update_network() called"))

    def get_all_ports(self, tenant_id, net_id, **kwargs):
        """
        This is probably not applicable to the Nexus plugin.
        Delete if not required.
        """
        LOG.debug(_("NexusPlugin:get_all_ports() called"))

    def create_port(self, tenant_id, net_id, port_state, port_id, **kwargs):
        """
        This is probably not applicable to the Nexus plugin.
        Delete if not required.
        """
        LOG.debug(_("NexusPlugin:create_port() called"))

    def delete_port(self, device_id, vlan_id):
        """
        Delete port bindings from the database and scan
        whether the network is still required on
        the interfaces trunked
        """
        LOG.debug(_("NexusPlugin:delete_port() called"))
        # Delete DB row for this port
        row = nxos_db.get_nexusvm_binding(vlan_id, device_id)
        if row:
            nxos_db.remove_nexusport_binding(row['port_id'], row['vlan_id'],
                                             row['switch_ip'],
                                             row['instance_id'])
            # Check for any other bindings with the same vlan_id and switch_ip
            bindings = nxos_db.get_nexusvlan_binding(
                row['vlan_id'], row['switch_ip'])

            if not bindings:
                # Delete this vlan from this switch
                _nexus_ip = row['switch_ip']
                _nexus_ports = (row['port_id'],)
                _nexus_ssh_port = \
                    self._nexus_switches[_nexus_ip, 'ssh_port']
                _nexus_creds = self.get_credential(_nexus_ip)
                _nexus_username = _nexus_creds['username']
                _nexus_password = _nexus_creds['password']
                self._client.delete_vlan(
                    str(row['vlan_id']), _nexus_ip,
                    _nexus_username, _nexus_password,
                    _nexus_ports, _nexus_ssh_port)

            return row['instance_id']

    def update_port(self, tenant_id, net_id, port_id, port_state, **kwargs):
        """
        This is probably not applicable to the Nexus plugin.
        Delete if not required.
        """
        LOG.debug(_("NexusPlugin:update_port() called"))

    def get_port_details(self, tenant_id, net_id, port_id, **kwargs):
        """
        This is probably not applicable to the Nexus plugin.
        Delete if not required.
        """
        LOG.debug(_("NexusPlugin:get_port_details() called"))

    def plug_interface(self, tenant_id, net_id, port_id, remote_interface_id,
                       **kwargs):
        """
        This is probably not applicable to the Nexus plugin.
        Delete if not required.
        """
        LOG.debug(_("NexusPlugin:plug_interface() called"))

    def unplug_interface(self, tenant_id, net_id, port_id, **kwargs):
        """
        This is probably not applicable to the Nexus plugin.
        Delete if not required.
        """
        LOG.debug(_("NexusPlugin:unplug_interface() called"))

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
