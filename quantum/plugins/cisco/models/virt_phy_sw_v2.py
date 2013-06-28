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
# @author: Rohit Agarwalla, Cisco Systems, Inc.
#

from copy import deepcopy
import inspect
import logging

from keystoneclient.v2_0 import client as keystone_client
from novaclient.v1_1 import client as nova_client

from quantum.db import l3_db
from quantum.manager import QuantumManager
from quantum.openstack.common import importutils
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.common import cisco_credentials_v2 as cred
from quantum.plugins.cisco.db import network_db_v2 as cdb
from quantum.plugins.cisco import l2network_plugin_configuration as conf
from quantum.plugins.openvswitch import ovs_db_v2 as odb
from quantum import quantum_plugin_base_v2
from quantum.db import api as db_api


LOG = logging.getLogger(__name__)


class VirtualPhysicalSwitchModelV2(quantum_plugin_base_v2.QuantumPluginBaseV2):
    """
    This implementation works with OVS and Nexus plugin for the
    following topology:
    One or more servers to a nexus switch.
    """
    MANAGE_STATE = True
    __native_bulk_support = True
    supported_extension_aliases = []
    _plugins = {}
    _inventory = {}
    _methods_to_delegate = ['create_network_bulk',
                            'get_network', 'get_networks',
                            'create_port_bulk',
                            'get_port', 'get_ports',
                            'create_subnet', 'create_subnet_bulk',
                            'delete_subnet', 'update_subnet',
                            'get_subnet', 'get_subnets', ]

    def __init__(self):
        """
        Initialize the segmentation manager, check which device plugins are
        configured, and load the inventories those device plugins for which the
        inventory is configured
        """
        for key in conf.PLUGINS[const.PLUGINS].keys():
            plugin_obj = conf.PLUGINS[const.PLUGINS][key]
            self._plugins[key] = importutils.import_object(plugin_obj)
            LOG.debug(_("Loaded device plugin %s\n"),
                      conf.PLUGINS[const.PLUGINS][key])
            if key in conf.PLUGINS[const.INVENTORY].keys():
                inventory_obj = conf.PLUGINS[const.INVENTORY][key]
                self._inventory[key] = importutils.import_object(inventory_obj)
                LOG.debug(_("Loaded device inventory %s\n"),
                          conf.PLUGINS[const.INVENTORY][key])

        if ((const.VSWITCH_PLUGIN in self._plugins) and
            hasattr(self._plugins[const.VSWITCH_PLUGIN],
                    "supported_extension_aliases")):
            self.supported_extension_aliases.extend(
                self._plugins[const.VSWITCH_PLUGIN].
                supported_extension_aliases)

        # At this point, all the database models should have been loaded. It's
        # possible that configure_db() may have been called by one of the
        # plugins loaded in above. Otherwise, this call is to make sure that
        # the database is initialized
        db_api.configure_db()

        # Initialize credential store after database initialization
        cred.Store.initialize()
        LOG.debug(_("%(module)s.%(name)s init done"),
                  {'module': __name__,
                   'name': self.__class__.__name__})

    def __getattribute__(self, name):
        """
        This delegates the calls to the methods implemented only by the OVS
        sub-plugin. Note: Currently, bulking is handled by the caller
        (PluginV2), and this model class expects to receive only non-bulking
        calls. If, however, a bulking call is made, this will method will
        delegate the call to the OVS plugin.
        """
        super_getattribute = super(VirtualPhysicalSwitchModelV2,
                                   self).__getattribute__
        methods = super_getattribute('_methods_to_delegate')

        if name in methods:
            plugin = super_getattribute('_plugins')[const.VSWITCH_PLUGIN]
            return getattr(plugin, name)

        try:
            return super_getattribute(name)
        except AttributeError:
            plugin = super_getattribute('_plugins')[const.VSWITCH_PLUGIN]
            return getattr(plugin, name)

    def _func_name(self, offset=0):
        """Get the name of the calling function"""
        frame_record = inspect.stack()[1 + offset]
        func_name = frame_record[3]
        return func_name

    def _invoke_plugin_per_device(self, plugin_key, function_name, args):
        """
        Invokes a device plugin's relevant functions (on the it's
        inventory and plugin implementation) for completing this operation.
        """
        if plugin_key not in self._plugins:
            LOG.info(_("No %s Plugin loaded"), plugin_key)
            LOG.info(_("%(plugin_key)s: %(function_name)s with args %(args)s "
                     "ignored"), locals())
            return
        device_params = self._invoke_inventory(plugin_key, function_name,
                                               args)
        device_ips = device_params[const.DEVICE_IP]
        if not device_ips:
            return [self._invoke_plugin(plugin_key, function_name, args,
                                        device_params)]
        else:
            output = []
            for device_ip in device_ips:
                new_device_params = deepcopy(device_params)
                new_device_params[const.DEVICE_IP] = device_ip
                output.append(self._invoke_plugin(plugin_key, function_name,
                                                  args, new_device_params))
            return output

    def _invoke_inventory(self, plugin_key, function_name, args):
        """
        Invokes the relevant function on a device plugin's
        inventory for completing this operation.
        """
        if plugin_key not in self._inventory:
            LOG.info(_("No %s inventory loaded"), plugin_key)
            LOG.info(_("%(plugin_key)s: %(function_name)s with args %(args)s "
                     "ignored"), locals())
            return {const.DEVICE_IP: []}
        else:
            return getattr(self._inventory[plugin_key], function_name)(args)

    def _invoke_plugin(self, plugin_key, function_name, args, kwargs):
        """
        Invokes the relevant function on a device plugin's
        implementation for completing this operation.
        """
        func = getattr(self._plugins[plugin_key], function_name)
        func_args_len = int(inspect.getargspec(func).args.__len__()) - 1
        fargs, varargs, varkw, defaults = inspect.getargspec(func)
        if args.__len__() > func_args_len:
            func_args = args[:func_args_len]
            extra_args = args[func_args_len:]
            for dict_arg in extra_args:
                for k, v in dict_arg.iteritems():
                    kwargs[k] = v
            return func(*func_args, **kwargs)
        else:
            if (varkw == 'kwargs'):
                return func(*args, **kwargs)
            else:
                return func(*args)

    def _get_segmentation_id(self, network_id):
        binding_seg_id = odb.get_network_binding(None, network_id)
        return binding_seg_id.segmentation_id

    def _get_all_segmentation_ids(self):
        vlan_ids = cdb.get_ovs_vlans()
        vlanids = ''
        for v_id in vlan_ids:
            if int(v_id) > 0:
                vlanids = str(v_id) + ',' + vlanids
        return vlanids.strip(',')

    def _validate_vlan_id(self, vlan_id):
        if vlan_id and int(vlan_id) > 1:
            return True
        else:
            return False

    def _get_instance_host(self, tenant_id, instance_id):
        keystone = cred._creds_dictionary['keystone']
        kc = keystone_client.Client(username=keystone['username'],
                                    password=keystone['password'],
                                    tenant_id=tenant_id,
                                    auth_url=keystone['auth_url'])
        tenant = kc.tenants.get(tenant_id)
        tenant_name = tenant.name

        nc = nova_client.Client(keystone['username'],
                                keystone['password'],
                                tenant_name,
                                keystone['auth_url'],
                                no_cache=True)
        serv = nc.servers.get(instance_id)
        host = serv.__getattr__('OS-EXT-SRV-ATTR:host')

        return host

    def create_network(self, context, network):
        """
        Perform this operation in the context of the configured device
        plugins.
        """
        LOG.debug(_("create_network() called"))
        try:
            args = [context, network]
            ovs_output = self._invoke_plugin_per_device(const.VSWITCH_PLUGIN,
                                                        self._func_name(),
                                                        args)
            vlan_id = self._get_segmentation_id(ovs_output[0]['id'])
            if not self._validate_vlan_id(vlan_id):
                return ovs_output[0]
            vlan_name = conf.VLAN_NAME_PREFIX + str(vlan_id)
            vlanids = self._get_all_segmentation_ids()
            args = [ovs_output[0]['tenant_id'], ovs_output[0]['name'],
                    ovs_output[0]['id'], vlan_name, vlan_id,
                    {'vlan_ids': vlanids}]
            return ovs_output[0]
        except:
            # TODO (Sumit): Check if we need to perform any rollback here
            raise

    def update_network(self, context, id, network):
        """
        Perform this operation in the context of the configured device
        plugins.
        """
        LOG.debug(_("update_network() called"))
        args = [context, id, network]
        ovs_output = self._invoke_plugin_per_device(const.VSWITCH_PLUGIN,
                                                    self._func_name(),
                                                    args)
        vlan_id = self._get_segmentation_id(ovs_output[0]['id'])
        if not self._validate_vlan_id(vlan_id):
            return ovs_output[0]
        vlanids = self._get_all_segmentation_ids()
        args = [ovs_output[0]['tenant_id'], id, {'vlan_id': vlan_id},
                {'net_admin_state': ovs_output[0]['admin_state_up']},
                {'vlan_ids': vlanids}]
        nexus_output = self._invoke_plugin_per_device(const.NEXUS_PLUGIN,
                                                      self._func_name(),
                                                      args)
        return ovs_output[0]

    def delete_network(self, context, id):
        """
        Perform this operation in the context of the configured device
        plugins.
        """
        try:
            base_plugin_ref = QuantumManager.get_plugin()
            n = base_plugin_ref.get_network(context, id)
            tenant_id = n['tenant_id']
            vlan_id = self._get_segmentation_id(id)
            args = [context, id]
            ovs_output = self._invoke_plugin_per_device(const.VSWITCH_PLUGIN,
                                                        self._func_name(),
                                                        args)
            args = [tenant_id, id, {const.VLANID: vlan_id},
                    {const.CONTEXT: context},
                    {const.BASE_PLUGIN_REF: base_plugin_ref}]
            if self._validate_vlan_id(vlan_id):
                self._invoke_plugin_per_device(const.NEXUS_PLUGIN,
                                               self._func_name(), args)
            return ovs_output[0]
        except:
            raise

    def get_network(self, context, id, fields=None):
        """For this model this method will be delegated to vswitch plugin"""
        pass

    def get_networks(self, context, filters=None, fields=None):
        """For this model this method will be delegated to vswitch plugin"""
        pass

    def _invoke_nexus_for_net_create(self, context, tenant_id, net_id,
                                     instance_id):
        net_dict = self.get_network(context, net_id)
        net_name = net_dict['name']

        vlan_id = self._get_segmentation_id(net_id)
        host = self._get_instance_host(tenant_id, instance_id)

        # Trunk segmentation id for only this host
        vlan_name = conf.VLAN_NAME_PREFIX + str(vlan_id)
        n_args = [tenant_id, net_name, net_id,
                  vlan_name, vlan_id, host, instance_id]
        nexus_output = self._invoke_plugin_per_device(
            const.NEXUS_PLUGIN,
            'create_network',
            n_args)

        return nexus_output

    def create_port(self, context, port):
        """
        Perform this operation in the context of the configured device
        plugins.
        """
        LOG.debug(_("create_port() called"))
        try:
            args = [context, port]
            ovs_output = self._invoke_plugin_per_device(const.VSWITCH_PLUGIN,
                                                        self._func_name(),
                                                        args)

            instance_id = port['port']['device_id']
            device_owner = port['port']['device_owner']

            if instance_id and device_owner != 'network:dhcp':
                net_id = port['port']['network_id']
                tenant_id = port['port']['tenant_id']
                self._invoke_nexus_for_net_create(
                    context, tenant_id, net_id, instance_id)

            return ovs_output[0]
        except:
            # TODO (asomya): Check if we need to perform any rollback here
            raise

    def get_port(self, context, id, fields=None):
        """For this model this method will be delegated to vswitch plugin"""
        pass

    def get_ports(self, context, filters=None, fields=None):
        """For this model this method will be delegated to vswitch plugin"""
        pass

    def update_port(self, context, id, port):
        """
        Perform this operation in the context of the configured device
        plugins.
        """
        LOG.debug(_("update_port() called"))
        try:
            # Get port
            old_port = self.get_port(context, id)
            # Check old port device_id
            old_device = old_port['device_id']
            # Update port with vswitch plugin
            args = [context, id, port]
            ovs_output = self._invoke_plugin_per_device(const.VSWITCH_PLUGIN,
                                                        self._func_name(),
                                                        args)
            net_id = old_port['network_id']
            instance_id = ''
            if 'device_id' in port['port']:
                instance_id = port['port']['device_id']

            # Check if there's a new device_id
            if instance_id and not old_device:
                tenant_id = old_port['tenant_id']
                self._invoke_nexus_for_net_create(
                    context, tenant_id, net_id, instance_id)

            return ovs_output[0]
        except:
            raise

    def delete_port(self, context, id):
        """
        Perform this operation in the context of the configured device
        plugins.
        """
        LOG.debug(_("delete_port() called"))
        try:
            args = [context, id]
            port = self.get_port(context, id)
            vlan_id = self._get_segmentation_id(port['network_id'])
            n_args = [port['device_id'], vlan_id]
            ovs_output = self._invoke_plugin_per_device(const.VSWITCH_PLUGIN,
                                                        self._func_name(),
                                                        args)
            nexus_output = self._invoke_plugin_per_device(const.NEXUS_PLUGIN,
                                                          self._func_name(),
                                                          n_args)
            return ovs_output[0]
        except:
            # TODO (asomya): Check if we need to perform any rollback here
            raise

    def create_subnet(self, context, subnet):
        """For this model this method will be delegated to vswitch plugin"""
        pass

    def update_subnet(self, context, id, subnet):
        """For this model this method will be delegated to vswitch plugin"""
        pass

    def get_subnet(self, context, id, fields=None):
        """For this model this method will be delegated to vswitch plugin"""
        pass

    def delete_subnet(self, context, id, kwargs):
        """For this model this method will be delegated to vswitch plugin"""
        pass

    def get_subnets(self, context, filters=None, fields=None):
        """For this model this method will be delegated to vswitch plugin"""
        pass
