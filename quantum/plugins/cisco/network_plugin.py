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

import inspect
import logging

from quantum.common import exceptions as exc
from quantum.db import db_base_plugin_v2
from quantum.db import models_v2
from quantum.openstack.common import importutils
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.common import cisco_credentials_v2 as cred
from quantum.plugins.cisco.common import cisco_exceptions as cexc
from quantum.plugins.cisco.common import cisco_utils as cutil
from quantum.plugins.cisco.db import network_db_v2 as cdb
from quantum.plugins.cisco import l2network_plugin_configuration as conf
from quantum.quantum_plugin_base import QuantumPluginBase

LOG = logging.getLogger(__name__)


class PluginV2(db_base_plugin_v2.QuantumDbPluginV2):
    """
    Plugin with v2 API support for multiple sub-plugins
    """
    supported_extension_aliases = ["Cisco Credential", "Cisco Port Profile",
                                   "Cisco qos", "Cisco Nova Tenant",
                                   "Cisco Multiport"]

    """
    Core API implementation
    """
    def __init__(self):
        """
        Initializes the DB, and credential store.
        """
        cdb.initialize()
        cred.Store.initialize()
        self._model = importutils.import_object(conf.MODEL_CLASS)
        super(PluginV2, self).__init__()
        LOG.debug("Plugin initialization complete")

    def create_network(self, context, network):
        """
        Creates a new Virtual Network, and assigns it
        a symbolic name.
        """
        LOG.debug("create_network() called\n")
        new_network = super(PluginV2, self).create_network(context, network)
        try:
            self._invoke_device_plugins(self._func_name(), [context,
                                                            new_network])
            return new_network
        except:
            super(PluginV2, self).delete_network(context, new_network['id'])
            raise

    def update_network(self, context, id, network):
        """
        Updates the symbolic name belonging to a particular
        Virtual Network.
        """
        LOG.debug("update_network() called\n")
        try:
            self._invoke_device_plugins(self._func_name(), [context, id,
                                                            network])
            return super(PluginV2, self).update_network(context, id, network)
        except:
            raise

    def delete_network(self, context, id):
        """
        Deletes the network with the specified network identifier
        belonging to the specified tenant.
        """
        LOG.debug("delete_network() called\n")
        #We first need to check if there are any ports on this network
        with context.session.begin():
            network = self._get_network(context, id)

            filter = {'network_id': [id]}
            ports = self.get_ports(context, filters=filter)
            if ports:
                raise exc.NetworkInUse(net_id=id)
        context.session.close()
        #Network does not have any ports, we can proceed to delete
        try:
            network = self._get_network(context, id)
            kwargs = {const.NETWORK: network,
                      const.BASE_PLUGIN_REF: self}
            self._invoke_device_plugins(self._func_name(), [context, id,
                                                            kwargs])
            return super(PluginV2, self).delete_network(context, id)
        except:
            raise

    def create_port(self, context, port):
        """
        Creates a port on the specified Virtual Network.
        """
        LOG.debug("create_port() called\n")
        new_port = super(PluginV2, self).create_port(context, port)
        try:
            self._invoke_device_plugins(self._func_name(), [context, new_port])
            return new_port
        except:
            super(PluginV2, self).delete_port(context, new_port['id'])
            raise

    def delete_port(self, context, id):
        """
        Deletes a port
        """
        LOG.debug("delete_port() called\n")
        port = self._get_port(context, id)
        """
        TODO (Sumit): Disabling this check for now, check later
        #Allow deleting a port only if the administrative state is down,
        #and its operation status is also down
        if port['admin_state_up'] or port['status'] == 'ACTIVE':
            raise exc.PortInUse(port_id=id, net_id=port['network_id'],
                                att_id=port['device_id'])
        """
        try:
            kwargs = {const.PORT: port}
            # TODO (Sumit): Might first need to check here if port is active
            self._invoke_device_plugins(self._func_name(), [context, id,
                                                            kwargs])
            return super(PluginV2, self).delete_port(context, id)
        except:
            raise

    def update_port(self, context, id, port):
        """
        Updates the state of a port and returns the updated port
        """
        LOG.debug("update_port() called\n")
        try:
            self._invoke_device_plugins(self._func_name(), [context, id,
                                                            port])
            return super(PluginV2, self).update_port(context, id, port)
        except:
            raise

    def create_subnet(self, context, subnet):
        """
        Create a subnet, which represents a range of IP addresses
        that can be allocated to devices.
        """
        LOG.debug("create_subnet() called\n")
        new_subnet = super(PluginV2, self).create_subnet(context, subnet)
        try:
            self._invoke_device_plugins(self._func_name(), [context,
                                                            new_subnet])
            return new_subnet
        except:
            super(PluginV2, self).delete_subnet(context, new_subnet['id'])
            raise

    def update_subnet(self, context, id, subnet):
        """
        Updates the state of a subnet and returns the updated subnet
        """
        LOG.debug("update_subnet() called\n")
        try:
            self._invoke_device_plugins(self._func_name(), [context, id,
                                                            subnet])
            return super(PluginV2, self).update_subnet(context, id, subnet)
        except:
            raise

    def delete_subnet(self, context, id):
        """
        Deletes a subnet
        """
        LOG.debug("delete_subnet() called\n")
        with context.session.begin():
            subnet = self._get_subnet(context, id)
            # Check if ports are using this subnet
            allocated_qry = context.session.query(models_v2.IPAllocation)
            allocated = allocated_qry.filter_by(subnet_id=id).all()
            if allocated:
                raise exc.SubnetInUse(subnet_id=id)
        context.session.close()
        try:
            kwargs = {const.SUBNET: subnet}
            self._invoke_device_plugins(self._func_name(), [context, id,
                                                            kwargs])
            return super(PluginV2, self).delete_subnet(context, id)
        except:
            raise

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
        host_list = self._invoke_device_plugins(self._func_name(),
                                                [tenant_id,
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
            db.validate_network_ownership(tenant_id, net_id)
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
        return getattr(self._model, function_name)(*args)

    def _func_name(self, offset=0):
        """Getting the name of the calling funciton"""
        return inspect.stack()[1 + offset][3]
