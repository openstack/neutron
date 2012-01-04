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

import inspect
import logging
import re

from quantum.common import exceptions as exc
from quantum.common import utils
from quantum.quantum_plugin_base import QuantumPluginBase

from quantum.plugins.cisco import l2network_plugin_configuration as conf
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.common import cisco_credentials as cred
from quantum.plugins.cisco.common import cisco_exceptions as cexc
from quantum.plugins.cisco.common import cisco_utils as cutil
from quantum.plugins.cisco.db import api as db
from quantum.plugins.cisco.db import l2network_db as cdb

LOG = logging.getLogger(__name__)


class L2Network(QuantumPluginBase):
    """ L2 Network Framework Plugin """
    supported_extension_aliases = ["Cisco Multiport", "Cisco Credential",
                                   "Cisco Port Profile", "Cisco qos",
                                   "Cisco Nova Tenant"]

    def __init__(self):
        cdb.initialize()
        cred.Store.initialize()
        self._model = utils.import_object(conf.MODEL_CLASS)
        self._vlan_mgr = utils.import_object(conf.MANAGER_CLASS)
        LOG.debug("L2Network plugin initialization done successfully\n")

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
        self._invoke_device_plugins(self._func_name(), [tenant_id])
        networks_list = db.network_list(tenant_id)
        new_networks_list = []
        for network in networks_list:
            new_network_dict = cutil.make_net_dict(network[const.UUID],
                                                   network[const.NETWORKNAME],
                                                   [])
            new_networks_list.append(new_network_dict)

        return new_networks_list

    def create_network(self, tenant_id, net_name, **kwargs):
        """
        Creates a new Virtual Network, and assigns it
        a symbolic name.
        """
        LOG.debug("create_network() called\n")
        new_network = db.network_create(tenant_id, net_name)
        new_net_id = new_network[const.UUID]
        vlan_id = self._get_vlan_for_tenant(tenant_id, net_name)
        vlan_name = self._get_vlan_name(new_net_id, str(vlan_id))
        self._invoke_device_plugins(self._func_name(), [tenant_id, net_name,
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
                    self.delete_port(tenant_id, net_id, port[const.UUID])

            self._invoke_device_plugins(self._func_name(), [tenant_id, net_id])
            net_dict = cutil.make_net_dict(net[const.UUID],
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
        network = db.network_get(net_id)
        self._invoke_device_plugins(self._func_name(), [tenant_id, net_id])
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
        LOG.debug("update_network() called\n")
        network = db.network_update(net_id, tenant_id, **kwargs)
        self._invoke_device_plugins(self._func_name(), [tenant_id, net_id,
                                                     kwargs])
        net_dict = cutil.make_net_dict(network[const.UUID],
                                       network[const.NETWORKNAME],
                                       [])
        return net_dict

    def get_all_ports(self, tenant_id, net_id):
        """
        Retrieves all port identifiers belonging to the
        specified Virtual Network.
        """
        LOG.debug("get_all_ports() called\n")
        network = db.network_get(net_id)
        self._invoke_device_plugins(self._func_name(), [tenant_id, net_id])
        ports_list = network[const.NETWORKPORTS]
        ports_on_net = []
        for port in ports_list:
            new_port = cutil.make_port_dict(port[const.UUID],
                                            port[const.PORTSTATE],
                                            port[const.NETWORKID],
                                            port[const.INTERFACEID])
            ports_on_net.append(new_port)

        return ports_on_net

    def create_port(self, tenant_id, net_id, port_state=None, **kwargs):
        """
        Creates a port on the specified Virtual Network.
        """
        LOG.debug("create_port() called\n")

        port = db.port_create(net_id, port_state)
        unique_port_id_string = port[const.UUID]
        self._invoke_device_plugins(self._func_name(), [tenant_id, net_id,
                                                     port_state,
                                                     unique_port_id_string])
        new_port_dict = cutil.make_port_dict(port[const.UUID],
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
        network = db.network_get(net_id)
        port = db.port_get(net_id, port_id)
        attachment_id = port[const.INTERFACEID]
        if not attachment_id:
            self._invoke_device_plugins(self._func_name(), [tenant_id,
                                                            net_id,
                                                            port_id])
            db.port_destroy(net_id, port_id)
            new_port_dict = cutil.make_port_dict(port_id, None, None, None)
            return new_port_dict
        else:
            raise exc.PortInUse(port_id=port_id, net_id=net_id,
                                att_id=attachment_id)

    def update_port(self, tenant_id, net_id, port_id, **kwargs):
        """
        Updates the state of a port on the specified Virtual Network.
        """
        LOG.debug("update_port() called\n")
        network = db.network_get(net_id)
        self._invoke_device_plugins(self._func_name(), [tenant_id, net_id,
                                        port_id, kwargs])
        self._validate_port_state(kwargs["state"])
        db.port_update(port_id, net_id, **kwargs)

        new_port_dict = cutil.make_port_dict(port_id, kwargs["state"], net_id,
                                             None)
        return new_port_dict

    def get_port_details(self, tenant_id, net_id, port_id):
        """
        This method allows the user to retrieve a remote interface
        that is attached to this particular port.
        """
        LOG.debug("get_port_details() called\n")
        network = db.network_get(net_id)
        self._invoke_device_plugins(self._func_name(), [tenant_id, net_id,
                                                     port_id])
        port = db.port_get(net_id, port_id)
        new_port_dict = cutil.make_port_dict(port[const.UUID],
                                             port[const.PORTSTATE],
                                             port[const.NETWORKID],
                                             port[const.INTERFACEID])
        return new_port_dict

    def plug_interface(self, tenant_id, net_id, port_id,
                       remote_interface_id):
        """
        Provides connectivity to a remote interface to the
        specified Virtual Network.
        """
        LOG.debug("plug_interface() called\n")
        network = db.network_get(net_id)
        port = db.port_get(net_id, port_id)
        attachment_id = port[const.INTERFACEID]
        if attachment_id is None:
            raise cexc.InvalidAttach(port_id=port_id, net_id=net_id,
                                    att_id=remote_interface_id)
        attachment_id = attachment_id[:const.UUID_LENGTH]
        remote_interface_id = remote_interface_id[:const.UUID_LENGTH]
        if remote_interface_id != attachment_id:
            LOG.debug("Existing attachment_id:%s, remote_interface_id:%s" % \
                      (attachment_id, remote_interface_id))
            raise exc.PortInUse(port_id=port_id, net_id=net_id,
                                att_id=attachment_id)
        self._invoke_device_plugins(self._func_name(), [tenant_id,
                                                        net_id, port_id,
                                                        attachment_id])
        db.port_unset_attachment(net_id, port_id)
        db.port_set_attachment(net_id, port_id, attachment_id)
        #Note: The remote_interface_id gets associated with the port
        # when the VM is instantiated. The plug interface call results
        # in putting the port on the VLAN associated with this network

    def unplug_interface(self, tenant_id, net_id, port_id):
        """
        Removes connectivity of a remote interface to the
        specified Virtual Network.
        """
        LOG.debug("unplug_interface() called\n")
        network = db.network_get(net_id)
        port = db.port_get(net_id, port_id)
        attachment_id = port[const.INTERFACEID]
        if attachment_id is None:
            raise exc.InvalidDetach(port_id=port_id, net_id=net_id,
                                    att_id=remote_interface_id)
        self._invoke_device_plugins(self._func_name(), [tenant_id, net_id,
                                                     port_id])
        attachment_id = attachment_id[:const.UUID_LENGTH]
        attachment_id = attachment_id + const.UNPLUGGED
        db.port_unset_attachment(net_id, port_id)
        db.port_set_attachment(net_id, port_id, attachment_id)

    """
    Extension API implementation
    """
    def get_all_portprofiles(self, tenant_id):
        """Get all port profiles"""
        LOG.debug("get_all_portprofiles() called\n")
        pplist = cdb.get_all_portprofiles()
        new_pplist = []
        for portprofile in pplist:
            new_pp = cutil.make_portprofile_dict(tenant_id,
                                                 portprofile[const.UUID],
                                                 portprofile[const.PPNAME],
                                                 portprofile[const.PPQOS])
            new_pplist.append(new_pp)

        return new_pplist

    def get_portprofile_details(self, tenant_id, profile_id):
        """Get port profile details"""
        LOG.debug("get_portprofile_details() called\n")
        try:
            portprofile = cdb.get_portprofile(tenant_id, profile_id)
        except Exception:
            raise cexc.PortProfileNotFound(tenant_id=tenant_id,
                                           portprofile_id=profile_id)

        new_pp = cutil.make_portprofile_dict(tenant_id,
                                             portprofile[const.UUID],
                                             portprofile[const.PPNAME],
                                             portprofile[const.PPQOS])
        return new_pp

    def create_portprofile(self, tenant_id, profile_name, qos):
        """Create port profile"""
        LOG.debug("create_portprofile() called\n")
        portprofile = cdb.add_portprofile(tenant_id, profile_name,
                                 const.NO_VLAN_ID, qos)
        new_pp = cutil.make_portprofile_dict(tenant_id,
                                             portprofile[const.UUID],
                                             portprofile[const.PPNAME],
                                             portprofile[const.PPQOS])
        return new_pp

    def delete_portprofile(self, tenant_id, profile_id):
        """Delete portprofile"""
        LOG.debug("delete_portprofile() called\n")
        try:
            portprofile = cdb.get_portprofile(tenant_id, profile_id)
        except Exception:
            raise cexc.PortProfileNotFound(tenant_id=tenant_id,
                                           portprofile_id=profile_id)

        plist = cdb.get_pp_binding(tenant_id, profile_id)
        if plist:
            raise cexc.PortProfileInvalidDelete(tenant_id=tenant_id,
                                                profile_id=profile_id)
        else:
            cdb.remove_portprofile(tenant_id, profile_id)

    def rename_portprofile(self, tenant_id, profile_id, new_name):
        """Rename port profile"""
        LOG.debug("rename_portprofile() called\n")
        try:
            portprofile = cdb.get_portprofile(tenant_id, profile_id)
        except Exception:
            raise cexc.PortProfileNotFound(tenant_id=tenant_id,
                                           portprofile_id=profile_id)
        portprofile = cdb.update_portprofile(tenant_id, profile_id, new_name)
        new_pp = cutil.make_portprofile_dict(tenant_id,
                                             portprofile[const.UUID],
                                             portprofile[const.PPNAME],
                                             portprofile[const.PPQOS])
        return new_pp

    def associate_portprofile(self, tenant_id, net_id,
                              port_id, portprofile_id):
        """Associate port profile"""
        LOG.debug("associate_portprofile() called\n")
        try:
            portprofile = cdb.get_portprofile(tenant_id, portprofile_id)
        except Exception:
            raise cexc.PortProfileNotFound(tenant_id=tenant_id,
                                           portprofile_id=portprofile_id)

        cdb.add_pp_binding(tenant_id, port_id, portprofile_id, False)

    def disassociate_portprofile(self, tenant_id, net_id,
                                 port_id, portprofile_id):
        """Disassociate port profile"""
        LOG.debug("disassociate_portprofile() called\n")
        try:
            portprofile = cdb.get_portprofile(tenant_id, portprofile_id)
        except Exception:
            raise cexc.PortProfileNotFound(tenant_id=tenant_id,
                                      portprofile_id=portprofile_id)

        cdb.remove_pp_binding(tenant_id, port_id, portprofile_id)

    def get_all_qoss(self, tenant_id):
        """Get all QoS levels"""
        LOG.debug("get_all_qoss() called\n")
        qoslist = cdb.get_all_qoss(tenant_id)
        return qoslist

    def get_qos_details(self, tenant_id, qos_id):
        """Get QoS Details"""
        LOG.debug("get_qos_details() called\n")
        try:
            qos_level = cdb.get_qos(tenant_id, qos_id)
        except Exception:
            raise cexc.QosNotFound(tenant_id=tenant_id,
                                   qos_id=qos_id)
        return qos_level

    def create_qos(self, tenant_id, qos_name, qos_desc):
        """Create a QoS level"""
        LOG.debug("create_qos() called\n")
        qos = cdb.add_qos(tenant_id, qos_name, str(qos_desc))
        return qos

    def delete_qos(self, tenant_id, qos_id):
        """Delete a QoS level"""
        LOG.debug("delete_qos() called\n")
        try:
            qos_level = cdb.get_qos(tenant_id, qos_id)
        except Exception:
            raise cexc.QosNotFound(tenant_id=tenant_id,
                                   qos_id=qos_id)
        return cdb.remove_qos(tenant_id, qos_id)

    def rename_qos(self, tenant_id, qos_id, new_name):
        """Rename QoS level"""
        LOG.debug("rename_qos() called\n")
        try:
            qos_level = cdb.get_qos(tenant_id, qos_id)
        except Exception:
            raise cexc.QosNotFound(tenant_id=tenant_id,
                                   qos_id=qos_id)
        qos = cdb.update_qos(tenant_id, qos_id, new_name)
        return qos

    def get_all_credentials(self, tenant_id):
        """Get all credentials"""
        LOG.debug("get_all_credentials() called\n")
        credential_list = cdb.get_all_credentials(tenant_id)
        return credential_list

    def get_credential_details(self, tenant_id, credential_id):
        """Get a particular credential"""
        LOG.debug("get_credential_details() called\n")
        try:
            credential = cdb.get_credential(tenant_id, credential_id)
        except Exception:
            raise cexc.CredentialNotFound(tenant_id=tenant_id,
                                          credential_id=credential_id)
        return credential

    def create_credential(self, tenant_id, credential_name, user_name,
                          password):
        """Create a new credential"""
        LOG.debug("create_credential() called\n")
        credential = cdb.add_credential(tenant_id, credential_name,
                                        user_name, password)
        return credential

    def delete_credential(self, tenant_id, credential_id):
        """Delete a credential"""
        LOG.debug("delete_credential() called\n")
        try:
            credential = cdb.get_credential(tenant_id, credential_id)
        except Exception:
            raise cexc.CredentialNotFound(tenant_id=tenant_id,
                                          credential_id=credential_id)
        credential = cdb.remove_credential(tenant_id, credential_id)
        return credential

    def rename_credential(self, tenant_id, credential_id, new_name):
        """Rename the particular credential resource"""
        LOG.debug("rename_credential() called\n")
        try:
            credential = cdb.get_credential(tenant_id, credential_id)
        except Exception:
            raise cexc.CredentialNotFound(tenant_id=tenant_id,
                                          credential_id=credential_id)
        credential = cdb.update_credential(tenant_id, credential_id, new_name)
        return credential

    def schedule_host(self, tenant_id, instance_id, instance_desc):
        """Provides the hostname on which a dynamic vnic is reserved"""
        LOG.debug("schedule_host() called\n")
        host_list = self._invoke_device_plugins(self._func_name(), [tenant_id,
                                                               instance_id,
                                                               instance_desc])
        return host_list

    def associate_port(self, tenant_id, instance_id, instance_desc):
        """
        Get the portprofile name and the device name for the dynamic vnic
        """
        LOG.debug("associate_port() called\n")
        return self._invoke_device_plugins(self._func_name(), [tenant_id,
                                                               instance_id,
                                                               instance_desc])

    def detach_port(self, tenant_id, instance_id, instance_desc):
        """
        Remove the association of the VIF with the dynamic vnic
        """
        LOG.debug("detach_port() called\n")
        return self._invoke_device_plugins(self._func_name(), [tenant_id,
                                                               instance_id,
                                                               instance_desc])

    def create_multiport(self, tenant_id, net_id_list, port_state, ports_desc):
        """
        Creates multiple ports on the specified Virtual Network.
        """
        LOG.debug("create_ports() called\n")
        ports_num = len(net_id_list)
        ports_id_list = []
        ports_dict_list = []

        for net_id in net_id_list:
            port = db.port_create(net_id, port_state)
            ports_id_list.append(port[const.UUID])
            port_dict = {const.PORT_ID: port[const.UUID]}
            ports_dict_list.append(port_dict)

        self._invoke_device_plugins(self._func_name(), [tenant_id,
                                                        net_id_list,
                                                        ports_num,
                                                        ports_id_list])
        return ports_dict_list

    """
    Private functions
    """
    def _invoke_device_plugins(self, function_name, args):
        """
        All device-specific calls are delegated to the model
        """
        return getattr(self._model, function_name)(args)

    def _get_vlan_for_tenant(self, tenant_id, net_name):
        """Get vlan ID"""
        return self._vlan_mgr.reserve_segmentation_id(tenant_id, net_name)

    def _release_vlan_for_tenant(self, tenant_id, net_id):
        """Relase VLAN"""
        return self._vlan_mgr.release_segmentation_id(tenant_id, net_id)

    def _get_vlan_name(self, net_id, vlan):
        """Getting the vlan name from the tenant and vlan"""
        vlan_name = conf.VLAN_NAME_PREFIX + vlan
        return vlan_name

    def _validate_port_state(self, port_state):
        """Checking the port state"""
        if port_state.upper() not in (const.PORT_UP, const.PORT_DOWN):
            raise exc.StateInvalid(port_state=port_state)
        return True

    def _func_name(self, offset=0):
        """Getting the name of the calling funciton"""
        return inspect.stack()[1 + offset][3]
