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
from quantum.plugins.cisco.db import api as db
from quantum.plugins.cisco.db import l2network_db as cdb

LOG.basicConfig(level=LOG.WARN)
LOG.getLogger(const.LOGGER_COMPONENT_NAME)


class L2Network(QuantumPluginBase):

    def __init__(self):
        self._vlan_counter = int(conf.VLAN_START) - 1
        self._model = utils.import_object(conf.MODEL_CLASS)
        cdb.initialize()
        # TODO (Sumit): The following should move to the segmentation module
        cdb.create_vlanids()

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
        networks_list = db.network_list(tenant_id)
        new_networks_list = []
        for network in networks_list:
            new_network_dict = self._make_net_dict(network[const.UUID],
                                                   network[const.NETWORKNAME],
                                                   [])
            new_networks_list.append(new_network_dict)

        return new_networks_list

    def create_network(self, tenant_id, net_name):
        """
        Creates a new Virtual Network, and assigns it
        a symbolic name.
        """
        LOG.debug("create_network() called\n")
        new_network = db.network_create(tenant_id, net_name)
        new_net_id = new_network[const.UUID]
        vlan_id = self._get_vlan_for_tenant(tenant_id, net_name)
        vlan_name = self._get_vlan_name(new_net_id, str(vlan_id))
        self._invokeDevicePlugins(self._funcName(), [tenant_id, net_name,
                                                     new_net_id, vlan_name,
                                                     vlan_id])
        cdb.add_vlan_binding(vlan_id, vlan_name, new_net_id)
        new_net_dict = {const.NET_ID: new_net_id,
                        const.NET_NAME: net_name,
                        const.NET_PORTS: []}

        return new_net_dict

    def delete_network(self, tenant_id, net_id):
        """
        Deletes the network with the specified network identifier
        belonging to the specified tenant.
        """
        LOG.debug("delete_network() called\n")
        net = db.network_get(net_id)
        if net:
            if len(net[const.NETWORKPORTS]) > 0:
                ports_on_net = db.port_list(net_id)
                for port in ports_on_net:
                    if port[const.INTERFACEID]:
                        raise exc.NetworkInUse(net_id=net_id)
                for port in ports_on_net:
                    self.delete_port(tenant_id, net_id, port[const.PORTID])

            self._invokeDevicePlugins(self._funcName(), [tenant_id, net_id])
            net_dict = self._make_net_dict(net[const.UUID],
                                           net[const.NETWORKNAME],
                                           [])
            self._release_vlan_for_tenant(tenant_id, net_id)
            cdb.remove_vlan_binding(net_id)
            db.network_destroy(net_id)
            return net_dict
        # Network not found
        raise exc.NetworkNotFound(net_id=net_id)

    def get_network_details(self, tenant_id, net_id):
        """
        Gets the details of a particular network
        """
        LOG.debug("get_network_details() called\n")
        self._invokeDevicePlugins(self._funcName(), [tenant_id, net_id])
        network = db.network_get(net_id)
        ports_list = network[const.NETWORKPORTS]
        ports_on_net = []
        for port in ports_list:
            new_port = self._make_port_dict(port[const.UUID],
                                            port[const.PORTSTATE],
                                            port[const.NETWORKID],
                                            port[const.INTERFACEID])
            ports_on_net.append(new_port)

        new_network = self._make_net_dict(network[const.UUID],
                                              network[const.NETWORKNAME],
                                              ports_on_net)

        return new_network

    def rename_network(self, tenant_id, net_id, new_name):
        """
        Updates the symbolic name belonging to a particular
        Virtual Network.
        """
        LOG.debug("rename_network() called\n")
        self._invokeDevicePlugins(self._funcName(), [tenant_id, net_id,
                                                     new_name])
        network = db.network_rename(tenant_id, net_id, new_name)
        net_dict = self._make_net_dict(network[const.UUID],
                                       network[const.NETWORKNAME],
                                       [])
        return net_dict

    def get_all_ports(self, tenant_id, net_id):
        """
        Retrieves all port identifiers belonging to the
        specified Virtual Network.
        """
        LOG.debug("get_all_ports() called\n")
        self._invokeDevicePlugins(self._funcName(), [tenant_id, net_id])
        network = db.network_get(net_id)
        ports_list = network[const.NETWORKPORTS]
        ports_on_net = []
        for port in ports_list:
            new_port = self._make_port_dict(port[const.UUID],
                                            port[const.PORTSTATE],
                                            port[const.NETWORKID],
                                            port[const.INTERFACEID])
            ports_on_net.append(new_port)

        return ports_on_net

    def create_port(self, tenant_id, net_id, port_state=None):
        """
        Creates a port on the specified Virtual Network.
        """
        LOG.debug("create_port() called\n")
        port = db.port_create(net_id, port_state)
        unique_port_id_string = port[const.UUID]
        self._invokeDevicePlugins(self._funcName(), [tenant_id, net_id,
                                                     port_state,
                                                     unique_port_id_string])
        new_port_dict = self._make_port_dict(port[const.UUID],
                                             port[const.PORTSTATE],
                                             port[const.NETWORKID],
                                             port[const.INTERFACEID])
        return new_port_dict

    def delete_port(self, tenant_id, net_id, port_id):
        """
        Deletes a port on a specified Virtual Network,
        if the port contains a remote interface attachment,
        the remote interface should first be un-plugged and
        then the port can be deleted.
        """
        LOG.debug("delete_port() called\n")
        self._invokeDevicePlugins(self._funcName(), [tenant_id, net_id,
                                                     port_id])
        db.port_destroy(net_id, port_id)
        new_port_dict = self._make_port_dict(port_id, None, None, None)
        return new_port_dict

    def update_port(self, tenant_id, net_id, port_id, port_state):
        """
        Updates the state of a port on the specified Virtual Network.
        """
        LOG.debug("update_port() called\n")
        self._invokeDevicePlugins(self._funcName(), [tenant_id, net_id,
                                                     port_id, port_state])
        self._validate_port_state(port_state)
        db.port_set_state(net_id, port_id, port_state)
        new_port_dict = self._make_port_dict(port_id, port_state, net_id,
                                             None)
        return new_port_dict

    def get_port_details(self, tenant_id, net_id, port_id):
        """
        This method allows the user to retrieve a remote interface
        that is attached to this particular port.
        """
        LOG.debug("get_port_details() called\n")
        self._invokeDevicePlugins(self._funcName(), [tenant_id, net_id,
                                                     port_id])
        port = db.port_get(net_id, port_id)
        new_port_dict = self._make_port_dict(port[const.UUID],
                                             port[const.PORTSTATE],
                                             port[const.NETWORKID],
                                             port[const.INTERFACEID])
        return new_port_dict

    def plug_interface(self, tenant_id, net_id, port_id,
                       remote_interface_id):
        """
        Attaches a remote interface to the specified port on the
        specified Virtual Network.
        """
        LOG.debug("plug_interface() called\n")
        self._invokeDevicePlugins(self._funcName(), [tenant_id, net_id,
                                                     port_id,
                                                     remote_interface_id])
        db.port_set_attachment(net_id, port_id, remote_interface_id)

    def unplug_interface(self, tenant_id, net_id, port_id):
        """
        Detaches a remote interface from the specified port on the
        specified Virtual Network.
        """
        LOG.debug("unplug_interface() called\n")
        self._invokeDevicePlugins(self._funcName(), [tenant_id, net_id,
                                                     port_id])
        db.port_unset_attachment(net_id, port_id)

    """
    Extension API implementation
    """
    def get_all_portprofiles(self, tenant_id):
        #return self._portprofiles.values()
        pplist = cdb.get_all_portprofiles()
        new_pplist = []
        for pp in pplist:
            new_pp = self._make_portprofile_dict(tenant_id,
                                                 pp[const.UUID],
                                                 pp[const.PPNAME],
                                                 pp[const.PPQOS])
            new_pplist.append(new_pp)

        return new_pplist

    def get_portprofile_details(self, tenant_id, profile_id):
        #return self._get_portprofile(tenant_id, profile_id)
        pp = cdb.get_portprofile(profile_id)
        new_pp = self._make_portprofile_dict(tenant_id,
                                             pp[const.UUID],
                                             pp[const.PPNAME],
                                             pp[const.PPQOS])
        return new_pp

    def create_portprofile(self, tenant_id, profile_name, qos):
        pp = cdb.add_portprofile(profile_name, const.NO_VLAN_ID, qos)
        new_pp = self._make_portprofile_dict(tenant_id,
                                             pp[const.UUID],
                                             pp[const.PPNAME],
                                             pp[const.PPQOS])
        return new_pp

    def delete_portprofile(self, tenant_id, profile_id):
        try:
            pp = cdb.get_portprofile(profile_id)
        except Exception, e:
            raise cexc.PortProfileNotFound(tenant_id=tenant_id,
                                      profile_id=profile_id)

        plist = cdb.get_pp_binding(profile_id)
        if plist:
            raise cexc.PortProfileInvalidDelete(tenant_id=tenant_id,
                                                portprofile_id=profile_id)
        else:
            cdb.remove_portprofile(profile_id)

    def rename_portprofile(self, tenant_id, profile_id, new_name):
        try:
            pp = cdb.get_portprofile(profile_id)
        except Exception, e:
            raise cexc.PortProfileNotFound(tenant_id=tenant_id,
                                           portprofile_id=profile_id)
        pp = cdb.update_portprofile(profile_id, new_name)
        new_pp = self._make_portprofile_dict(tenant_id,
                                             pp[const.UUID],
                                             pp[const.PPNAME],
                                             pp[const.PPQOS])
        return new_pp

    def associate_portprofile(self, tenant_id, net_id,
                              port_id, portprofile_id):
        try:
            pp = cdb.get_portprofile(portprofile_id)
        except Exception, e:
            raise cexc.PortProfileNotFound(tenant_id=tenant_id,
                                           portprofile_id=portprofile_id)

        cdb.add_pp_binding(tenant_id, port_id, portprofile_id, False)

    def disassociate_portprofile(self, tenant_id, net_id,
                                 port_id, portprofile_id):
        try:
            pp = cdb.get_portprofile(portprofile_id)
        except Exception, e:
            raise cexc.PortProfileNotFound(tenant_id=tenant_id,
                                      portprofile_id=portprofile_id)

        cdb.remove_pp_binding(port_id, portprofile_id)

    def create_defaultPProfile(self, tenant_id, network_id, profile_name,
                               qos):
        pp = cdb.add_portprofile(profile_name, const.NO_VLAN_ID, qos)
        new_pp = self._make_portprofile_dict(tenant_id,
                                             pp[const.UUID],
                                             pp[const.PPNAME],
                                             pp[const.PPQOS])
        cdb.add_pp_binding(tenant_id, port_id, portprofile_id, True)
        return new_pp

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
        return cdb.reserve_vlanid()

    def _release_vlan_for_tenant(self, tenant_id, net_id):
        vlan_binding = cdb.get_vlan_binding(net_id)
        return cdb.release_vlanid(vlan_binding[const.VLANID])

    def _get_vlan_name(self, net_id, vlan):
        vlan_name = conf.VLAN_NAME_PREFIX + vlan
        return vlan_name

    def _validate_port_state(self, port_state):
        if port_state.upper() not in (const.PORT_UP, const.PORT_DOWN):
            raise exc.StateInvalid(port_state=port_state)
        return True

    def _funcName(self, offset=0):
        return inspect.stack()[1 + offset][3]

    def _make_net_dict(self, net_id, net_name, ports):
        res = {const.NET_ID: str(net_id), const.NET_NAME: net_name}
        res[const.NET_PORTS] = ports
        return res

    def _make_port_dict(self, port_id, port_state, net_id, attachment):
        res = {const.PORT_ID: str(port_id), const.PORT_STATE: port_state}
        res[const.NET_ID] = net_id
        res[const.ATTACHMENT] = attachment
        return res

    def _make_portprofile_dict(self, tenant_id, profile_id, profile_name,
                               qos):
        profile_associations = self._make_portprofile_assc_list(profile_id)
        res = {const.PROFILE_ID: str(profile_id),
               const.PROFILE_NAME: profile_name,
               const.PROFILE_ASSOCIATIONS: profile_associations,
               const.PROFILE_VLAN_ID: None,
               const.PROFILE_QOS: qos}
        return res

    def _make_portprofile_assc_list(self, profile_id):
        plist = cdb.get_pp_binding(profile_id)
        assc_list = []
        for port in plist:
            assc_list.append(port[const.PORTID])

        return assc_list


def main():
    client = L2Network()
    """
    client.create_portprofile("12345", "tpp1", "2")
    client.create_portprofile("12345", "tpp2", "3")
    print ("%s\n") % client.get_all_portprofiles("12345")
    """

if __name__ == '__main__':
    main()
