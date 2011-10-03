"""
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
"""

import logging

from quantum.common import exceptions as exc
from quantum.common import utils
from quantum.plugins.cisco.common import cisco_exceptions as cexc
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.common import cisco_credentials as cred
from quantum.plugins.cisco.common import cisco_utils as cutil
from quantum.plugins.cisco.db import api as db
from quantum.plugins.cisco.db import l2network_db as cdb
from quantum.plugins.cisco.db import ucs_db as udb
from quantum.plugins.cisco.l2device_plugin_base import L2DevicePluginBase
from quantum.plugins.cisco.ucs import cisco_ucs_configuration as conf

LOG = logging.getLogger(__name__)


class UCSVICPlugin(L2DevicePluginBase):
    """UCS Device Plugin"""

    def __init__(self):
        self._driver = utils.import_object(conf.UCSM_DRIVER)
        LOG.debug("Loaded driver %s\n" % conf.UCSM_DRIVER)
        # TODO (Sumit) Make the counter per UCSM
        self._port_profile_counter = 0

    def get_all_networks(self, tenant_id, **kwargs):
        """
        Returns a dictionary containing all
        <network_uuid, network_name> for
        the specified tenant.
        """
        LOG.debug("UCSVICPlugin:get_all_networks() called\n")
        self._set_ucsm(kwargs[const.DEVICE_IP])
        networks_list = db.network_list(tenant_id)
        new_networks_list = []
        for network in networks_list:
            new_network_dict = cutil.make_net_dict(network[const.UUID],
                                                   network[const.NETWORKNAME],
                                                   [])
            new_networks_list.append(new_network_dict)

        return new_networks_list

    def create_network(self, tenant_id, net_name, net_id, vlan_name, vlan_id,
                       **kwargs):
        """
        Creates a new Virtual Network, and assigns it
        a symbolic name.
        """
        LOG.debug("UCSVICPlugin:create_network() called\n")
        self._set_ucsm(kwargs[const.DEVICE_IP])
        self._driver.create_vlan(vlan_name, str(vlan_id), self._ucsm_ip,
                                 self._ucsm_username, self._ucsm_password)
        network = db.network_get(net_id)
        ports_on_net = []
        new_network_dict = cutil.make_net_dict(network[const.UUID],
                                               network[const.NETWORKNAME],
                                               ports_on_net)
        return new_network_dict

    def delete_network(self, tenant_id, net_id, **kwargs):
        """
        Deletes the network with the specified network identifier
        belonging to the specified tenant.
        """
        LOG.debug("UCSVICPlugin:delete_network() called\n")
        self._set_ucsm(kwargs[const.DEVICE_IP])
        net = db.network_get(net_id)
        vlan_binding = cdb.get_vlan_binding(net[const.UUID])
        vlan_name = vlan_binding[const.VLANNAME]
        self._driver.delete_vlan(vlan_name, self._ucsm_ip,
                                 self._ucsm_username, self._ucsm_password)
        net_dict = cutil.make_net_dict(net[const.UUID],
                                       net[const.NETWORKNAME],
                                       [])
        return net_dict

    def get_network_details(self, tenant_id, net_id, **kwargs):
        """
        Deletes the Virtual Network belonging to a the
        spec
        """
        LOG.debug("UCSVICPlugin:get_network_details() called\n")
        self._set_ucsm(kwargs[const.DEVICE_IP])
        network = db.network_get(net_id)
        ports_list = network[const.NETWORKPORTS]
        ports_on_net = []
        for port in ports_list:
            new_port = cutil.make_port_dict(port[const.UUID],
                                            port[const.PORTSTATE],
                                            port[const.NETWORKID],
                                            port[const.INTERFACEID])
            ports_on_net.append(new_port)

        new_network = cutil.make_net_dict(network[const.UUID],
                                              network[const.NETWORKNAME],
                                              ports_on_net)

        return new_network

    def update_network(self, tenant_id, net_id, **kwargs):
        """
        Updates the symbolic name belonging to a particular
        Virtual Network.
        """
        LOG.debug("UCSVICPlugin:update_network() called\n")
        self._set_ucsm(kwargs[const.DEVICE_IP])
        network = db.network_get(net_id)
        net_dict = cutil.make_net_dict(network[const.UUID],
                                       network[const.NETWORKNAME],
                                       [])
        return net_dict

    def get_all_ports(self, tenant_id, net_id, **kwargs):
        """
        Retrieves all port identifiers belonging to the
        specified Virtual Network.
        """
        LOG.debug("UCSVICPlugin:get_all_ports() called\n")
        self._set_ucsm(kwargs[const.DEVICE_IP])
        network = db.network_get(net_id)
        ports_list = network[const.NETWORKPORTS]
        ports_on_net = []
        for port in ports_list:
            port_binding = udb.get_portbinding(port[const.UUID])
            ports_on_net.append(port_binding)

        return ports_on_net

    def create_port(self, tenant_id, net_id, port_state, port_id, **kwargs):
        """
        Creates a port on the specified Virtual Network.
        """
        LOG.debug("UCSVICPlugin:create_port() called\n")
        self._set_ucsm(kwargs[const.DEVICE_IP])
        qos = None
        ucs_inventory = kwargs[const.UCS_INVENTORY]
        least_rsvd_blade_dict = kwargs[const.LEAST_RSVD_BLADE_DICT]
        chassis_id = least_rsvd_blade_dict[const.LEAST_RSVD_BLADE_CHASSIS]
        blade_id = least_rsvd_blade_dict[const.LEAST_RSVD_BLADE_ID]
        blade_data_dict = least_rsvd_blade_dict[const.LEAST_RSVD_BLADE_DATA]
        new_port_profile = self._create_port_profile(tenant_id, net_id,
                                                     port_id,
                                                     conf.DEFAULT_VLAN_NAME,
                                                     conf.DEFAULT_VLAN_ID)
        profile_name = new_port_profile[const.PROFILE_NAME]
        rsvd_nic_dict = ucs_inventory.\
                reserve_blade_interface(self._ucsm_ip, chassis_id,
                                        blade_id, blade_data_dict,
                                        tenant_id, port_id,
                                        profile_name)
        port_binding = udb.update_portbinding(port_id,
                                       portprofile_name=profile_name,
                                       vlan_name=conf.DEFAULT_VLAN_NAME,
                                       vlan_id=conf.DEFAULT_VLAN_ID,
                                       qos=qos)
        return port_binding

    def delete_port(self, tenant_id, net_id, port_id, **kwargs):
        """
        Deletes a port on a specified Virtual Network,
        if the port contains a remote interface attachment,
        the remote interface should first be un-plugged and
        then the port can be deleted.
        """
        LOG.debug("UCSVICPlugin:delete_port() called\n")
        self._set_ucsm(kwargs[const.DEVICE_IP])
        ucs_inventory = kwargs[const.UCS_INVENTORY]
        chassis_id = kwargs[const.CHASSIS_ID]
        blade_id = kwargs[const.BLADE_ID]
        interface_dn = kwargs[const.BLADE_INTF_DN]
        port_binding = udb.get_portbinding(port_id)
        profile_name = port_binding[const.PORTPROFILENAME]
        self._delete_port_profile(port_id, profile_name)
        ucs_inventory.unreserve_blade_interface(self._ucsm_ip, chassis_id,
                                                blade_id, interface_dn)
        return udb.remove_portbinding(port_id)

    def update_port(self, tenant_id, net_id, port_id, **kwargs):
        """
        Updates the state of a port on the specified Virtual Network.
        """
        LOG.debug("UCSVICPlugin:update_port() called\n")
        self._set_ucsm(kwargs[const.DEVICE_IP])
        pass

    def get_port_details(self, tenant_id, net_id, port_id, **kwargs):
        """
        This method allows the user to retrieve a remote interface
        that is attached to this particular port.
        """
        LOG.debug("UCSVICPlugin:get_port_details() called\n")
        self._set_ucsm(kwargs[const.DEVICE_IP])
        port_binding = udb.get_portbinding(port_id)
        return port_binding

    def plug_interface(self, tenant_id, net_id, port_id, remote_interface_id,
                       **kwargs):
        """
        Attaches a remote interface to the specified port on the
        specified Virtual Network.
        """
        LOG.debug("UCSVICPlugin:plug_interface() called\n")
        self._set_ucsm(kwargs[const.DEVICE_IP])
        port_binding = udb.get_portbinding(port_id)
        profile_name = port_binding[const.PORTPROFILENAME]
        old_vlan_name = port_binding[const.VLANNAME]
        new_vlan_name = self._get_vlan_name_for_network(tenant_id, net_id)
        new_vlan_id = self._get_vlan_id_for_network(tenant_id, net_id)
        self._driver.change_vlan_in_profile(profile_name, old_vlan_name,
                                            new_vlan_name, self._ucsm_ip,
                                            self._ucsm_username,
                                            self._ucsm_password)
        return udb.update_portbinding(port_id, vlan_name=new_vlan_name,
                                      vlan_id=new_vlan_id)

    def unplug_interface(self, tenant_id, net_id, port_id, **kwargs):
        """
        Detaches a remote interface from the specified port on the
        specified Virtual Network.
        """
        LOG.debug("UCSVICPlugin:unplug_interface() called\n")
        self._set_ucsm(kwargs[const.DEVICE_IP])
        port_binding = udb.get_portbinding(port_id)
        profile_name = port_binding[const.PORTPROFILENAME]
        old_vlan_name = port_binding[const.VLANNAME]
        new_vlan_name = conf.DEFAULT_VLAN_NAME
        self._driver.change_vlan_in_profile(profile_name, old_vlan_name,
                                            new_vlan_name, self._ucsm_ip,
                                            self._ucsm_username,
                                            self._ucsm_password)
        return udb.update_portbinding(port_id, vlan_name=new_vlan_name,
                                      vlan_id=conf.DEFAULT_VLAN_ID)

    def create_multiport(self, tenant_id, net_id_list, ports_num, port_id_list,
                     **kwargs):
        """
        Creates a port on the specified Virtual Network.
        """
        LOG.debug("UCSVICPlugin:create_multiport() called\n")
        self._set_ucsm(kwargs[const.DEVICE_IP])
        qos = None
        ucs_inventory = kwargs[const.UCS_INVENTORY]
        least_rsvd_blade_dict = kwargs[const.LEAST_RSVD_BLADE_DICT]
        chassis_id = least_rsvd_blade_dict[const.LEAST_RSVD_BLADE_CHASSIS]
        blade_id = least_rsvd_blade_dict[const.LEAST_RSVD_BLADE_ID]
        blade_data_dict = least_rsvd_blade_dict[const.LEAST_RSVD_BLADE_DATA]
        port_binding_list = []
        for port_id, net_id in zip(port_id_list, net_id_list):
            new_port_profile = \
                    self._create_port_profile(tenant_id, net_id, port_id,
                                              conf.DEFAULT_VLAN_NAME,
                                              conf.DEFAULT_VLAN_ID)
            profile_name = new_port_profile[const.PROFILE_NAME]
            rsvd_nic_dict = ucs_inventory.\
                    reserve_blade_interface(self._ucsm_ip, chassis_id,
                                            blade_id, blade_data_dict,
                                            tenant_id, port_id,
                                            profile_name)
            port_binding = udb.update_portbinding(port_id,
                                           portprofile_name=profile_name,
                                           vlan_name=conf.DEFAULT_VLAN_NAME,
                                           vlan_id=conf.DEFAULT_VLAN_ID,
                                           qos=qos)
            port_binding_list.append(port_binding)
        return port_binding_list

    def detach_port(self, tenant_id, instance_id, instance_desc, **kwargs):
        """
        Remove the association of the VIF with the dynamic vnic
        """
        LOG.debug("detach_port() called\n")
        port_id = kwargs[const.PORTID]
        kwargs.pop(const.PORTID)
        return self.unplug_interface(tenant_id, None, port_id, **kwargs)

    def _get_profile_name(self, port_id):
        """Returns the port profile name based on the port UUID"""
        profile_name = conf.PROFILE_NAME_PREFIX \
                + cutil.get16ByteUUID(port_id)
        return profile_name

    def _get_vlan_name_for_network(self, tenant_id, network_id):
        """Return the VLAN name as set by the L2 network plugin"""
        vlan_binding = cdb.get_vlan_binding(network_id)
        return vlan_binding[const.VLANNAME]

    def _get_vlan_id_for_network(self, tenant_id, network_id):
        """Return the VLAN id as set by the L2 network plugin"""
        vlan_binding = cdb.get_vlan_binding(network_id)
        return vlan_binding[const.VLANID]

    def _create_port_profile(self, tenant_id, net_id, port_id, vlan_name,
                             vlan_id):
        """Create port profile in UCSM"""
        if self._port_profile_counter >= int(conf.MAX_UCSM_PORT_PROFILES):
            raise cexc.UCSMPortProfileLimit(net_id=net_id, port_id=port_id)
        profile_name = self._get_profile_name(port_id)
        self._driver.create_profile(profile_name, vlan_name, self._ucsm_ip,
                                    self._ucsm_username, self._ucsm_password)
        self._port_profile_counter += 1
        new_port_profile = {const.PROFILE_NAME: profile_name,
                            const.PROFILE_VLAN_NAME: vlan_name,
                            const.PROFILE_VLAN_ID: vlan_id}
        return new_port_profile

    def _delete_port_profile(self, port_id, profile_name):
        """Delete port profile in UCSM"""
        self._driver.delete_profile(profile_name, self._ucsm_ip,
                                    self._ucsm_username, self._ucsm_password)
        self._port_profile_counter -= 1

    def _set_ucsm(self, ucsm_ip):
        """Set the UCSM IP, username, and password"""
        self._ucsm_ip = ucsm_ip
        self._ucsm_username = cred.Store.getUsername(conf.UCSM_IP_ADDRESS)
        self._ucsm_password = cred.Store.getPassword(conf.UCSM_IP_ADDRESS)
