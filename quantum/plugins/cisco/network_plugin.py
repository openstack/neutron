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

from sqlalchemy import orm

from quantum.common import exceptions as exc
from quantum.db import db_base_plugin_v2
from quantum.db import models_v2
from quantum.openstack.common import importutils
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.common import cisco_exceptions as cexc
from quantum.plugins.cisco.common import config  # noqa
from quantum.plugins.cisco.db import network_db_v2 as cdb

LOG = logging.getLogger(__name__)


class PluginV2(db_base_plugin_v2.QuantumDbPluginV2):
    """
    Meta-Plugin with v2 API support for multiple sub-plugins.
    """
    supported_extension_aliases = ["Cisco Credential", "Cisco qos"]
    _methods_to_delegate = ['create_network',
                            'delete_network', 'update_network', 'get_network',
                            'get_networks',
                            'create_port', 'delete_port',
                            'update_port', 'get_port', 'get_ports',
                            'create_subnet',
                            'delete_subnet', 'update_subnet',
                            'get_subnet', 'get_subnets', ]
    _master = True

    def __init__(self):
        """
        Loads the model class.
        """
        self._model = importutils.import_object(config.CISCO.model_class)
        if hasattr(self._model, "MANAGE_STATE") and self._model.MANAGE_STATE:
            self._master = False
            LOG.debug(_("Model %s manages state"), config.CISCO.model_class)
            native_bulk_attr_name = ("_%s__native_bulk_support"
                                     % self._model.__class__.__name__)
            self.__native_bulk_support = getattr(self._model,
                                                 native_bulk_attr_name, False)

        if hasattr(self._model, "supported_extension_aliases"):
            self.supported_extension_aliases.extend(
                self._model.supported_extension_aliases)

        LOG.debug(_("Plugin initialization complete"))

    def __getattribute__(self, name):
        """
        When the configured model class offers to manage the state of the
        logical resources, we delegate the core API calls directly to it.
        Note: Bulking calls will be handled by this class, and turned into
        non-bulking calls to be considered for delegation.
        """
        master = object.__getattribute__(self, "_master")
        methods = object.__getattribute__(self, "_methods_to_delegate")
        if not master and name in methods:
            return getattr(object.__getattribute__(self, "_model"),
                           name)
        else:
            return object.__getattribute__(self, name)

    def __getattr__(self, name):
        """
        This delegates the calls to the extensions explicitly implemented by
        the model.
        """
        if hasattr(self._model, name):
            return getattr(self._model, name)
        else:
            # Must make sure we re-raise the error that led us here, since
            # otherwise getattr() and even hasattr() doesn't work corretly.
            raise AttributeError("'%s' object has no attribute '%s'" %
                                 (self._model, name))

    """
    Core API implementation
    """
    def create_network(self, context, network):
        """
        Creates a new Virtual Network, and assigns it
        a symbolic name.
        """
        LOG.debug(_("create_network() called"))
        new_network = super(PluginV2, self).create_network(context,
                                                           network)
        try:
            self._invoke_device_plugins(self._func_name(), [context,
                                                            new_network])
            return new_network
        except:
            super(PluginV2, self).delete_network(context,
                                                 new_network['id'])
            raise

    def update_network(self, context, id, network):
        """
        Updates the symbolic name belonging to a particular
        Virtual Network.
        """
        LOG.debug(_("update_network() called"))
        upd_net_dict = super(PluginV2, self).update_network(context, id,
                                                            network)
        self._invoke_device_plugins(self._func_name(), [context, id,
                                                        upd_net_dict])
        return upd_net_dict

    def delete_network(self, context, id):
        """
        Deletes the network with the specified network identifier
        belonging to the specified tenant.
        """
        LOG.debug(_("delete_network() called"))
        #We first need to check if there are any ports on this network
        with context.session.begin():
            network = self._get_network(context, id)
            filter = {'network_id': [id]}
            ports = self.get_ports(context, filters=filter)

            # check if there are any tenant owned ports in-use
            prefix = db_base_plugin_v2.AGENT_OWNER_PREFIX
            only_svc = all(p['device_owner'].startswith(prefix) for p in ports)
            if not only_svc:
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

    def get_network(self, context, id, fields=None):
        """
        Gets a particular network
        """
        LOG.debug(_("get_network() called"))
        return super(PluginV2, self).get_network(context, id, fields)

    def get_networks(self, context, filters=None, fields=None):
        """
        Gets all networks
        """
        LOG.debug(_("get_networks() called"))
        return super(PluginV2, self).get_networks(context, filters, fields)

    def create_port(self, context, port):
        """
        Creates a port on the specified Virtual Network.
        """
        LOG.debug(_("create_port() called"))
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
        LOG.debug(_("delete_port() called"))
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
        LOG.debug(_("update_port() called"))
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
        LOG.debug(_("create_subnet() called"))
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
        LOG.debug(_("update_subnet() called"))
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
        LOG.debug(_("delete_subnet() called"))
        with context.session.begin():
            subnet = self._get_subnet(context, id)
            # Check if ports are using this subnet
            allocated_qry = context.session.query(models_v2.IPAllocation)
            allocated_qry = allocated_qry.options(orm.joinedload('ports'))
            allocated = allocated_qry.filter_by(subnet_id=id).all()

            prefix = db_base_plugin_v2.AGENT_OWNER_PREFIX
            if not all(not a.port_id or a.ports.device_owner.startswith(prefix)
                       for a in allocated):
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
    def get_all_qoss(self, tenant_id):
        """Get all QoS levels"""
        LOG.debug(_("get_all_qoss() called"))
        qoslist = cdb.get_all_qoss(tenant_id)
        return qoslist

    def get_qos_details(self, tenant_id, qos_id):
        """Get QoS Details"""
        LOG.debug(_("get_qos_details() called"))
        try:
            qos_level = cdb.get_qos(tenant_id, qos_id)
        except Exception:
            raise cexc.QosNotFound(tenant_id=tenant_id,
                                   qos_id=qos_id)
        return qos_level

    def create_qos(self, tenant_id, qos_name, qos_desc):
        """Create a QoS level"""
        LOG.debug(_("create_qos() called"))
        qos = cdb.add_qos(tenant_id, qos_name, str(qos_desc))
        return qos

    def delete_qos(self, tenant_id, qos_id):
        """Delete a QoS level"""
        LOG.debug(_("delete_qos() called"))
        try:
            cdb.get_qos(tenant_id, qos_id)
        except Exception:
            raise cexc.QosNotFound(tenant_id=tenant_id,
                                   qos_id=qos_id)
        return cdb.remove_qos(tenant_id, qos_id)

    def rename_qos(self, tenant_id, qos_id, new_name):
        """Rename QoS level"""
        LOG.debug(_("rename_qos() called"))
        try:
            cdb.get_qos(tenant_id, qos_id)
        except Exception:
            raise cexc.QosNotFound(tenant_id=tenant_id,
                                   qos_id=qos_id)
        qos = cdb.update_qos(tenant_id, qos_id, new_name)
        return qos

    def get_all_credentials(self, tenant_id):
        """Get all credentials"""
        LOG.debug(_("get_all_credentials() called"))
        credential_list = cdb.get_all_credentials(tenant_id)
        return credential_list

    def get_credential_details(self, tenant_id, credential_id):
        """Get a particular credential"""
        LOG.debug(_("get_credential_details() called"))
        try:
            credential = cdb.get_credential(tenant_id, credential_id)
        except Exception:
            raise cexc.CredentialNotFound(tenant_id=tenant_id,
                                          credential_id=credential_id)
        return credential

    def create_credential(self, tenant_id, credential_name, user_name,
                          password):
        """Create a new credential"""
        LOG.debug(_("create_credential() called"))
        credential = cdb.add_credential(tenant_id, credential_name,
                                        user_name, password)
        return credential

    def delete_credential(self, tenant_id, credential_id):
        """Delete a credential"""
        LOG.debug(_("delete_credential() called"))
        try:
            credential = cdb.get_credential(tenant_id, credential_id)
        except Exception:
            raise cexc.CredentialNotFound(tenant_id=tenant_id,
                                          credential_id=credential_id)
        credential = cdb.remove_credential(tenant_id, credential_id)
        return credential

    def rename_credential(self, tenant_id, credential_id, new_name):
        """Rename the particular credential resource"""
        LOG.debug(_("rename_credential() called"))
        try:
            credential = cdb.get_credential(tenant_id, credential_id)
        except Exception:
            raise cexc.CredentialNotFound(tenant_id=tenant_id,
                                          credential_id=credential_id)
        credential = cdb.update_credential(tenant_id, credential_id, new_name)
        return credential

    def schedule_host(self, tenant_id, instance_id, instance_desc):
        """Provides the hostname on which a dynamic vnic is reserved"""
        LOG.debug(_("schedule_host() called"))
        host_list = self._invoke_device_plugins(self._func_name(),
                                                [tenant_id,
                                                 instance_id,
                                                 instance_desc])
        return host_list

    def associate_port(self, tenant_id, instance_id, instance_desc):
        """
        Get the portprofile name and the device name for the dynamic vnic
        """
        LOG.debug(_("associate_port() called"))
        return self._invoke_device_plugins(self._func_name(), [tenant_id,
                                                               instance_id,
                                                               instance_desc])

    def detach_port(self, tenant_id, instance_id, instance_desc):
        """
        Remove the association of the VIF with the dynamic vnic
        """
        LOG.debug(_("detach_port() called"))
        return self._invoke_device_plugins(self._func_name(), [tenant_id,
                                                               instance_id,
                                                               instance_desc])

    """
    Private functions
    """
    def _invoke_device_plugins(self, function_name, args):
        """
        Device-specific calls including core API and extensions are
        delegated to the model.
        """
        if hasattr(self._model, function_name):
            return getattr(self._model, function_name)(*args)

    def _func_name(self, offset=0):
        """Getting the name of the calling funciton"""
        return inspect.stack()[1 + offset][3]
