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

import inspect
import logging
import sys

from neutron.api.v2 import attributes
from neutron.db import api as db_api
from neutron.extensions import portbindings
from neutron.extensions import providernet as provider
from neutron import neutron_plugin_base_v2
from neutron.openstack.common import importutils
from neutron.plugins.cisco.common import cisco_constants as const
from neutron.plugins.cisco.common import cisco_credentials_v2 as cred
from neutron.plugins.cisco.common import cisco_exceptions as cexc
from neutron.plugins.cisco.common import config as conf
from neutron.plugins.cisco.db import network_db_v2 as cdb
from neutron.plugins.openvswitch import ovs_db_v2 as odb


LOG = logging.getLogger(__name__)


class VirtualPhysicalSwitchModelV2(neutron_plugin_base_v2.NeutronPluginBaseV2):
    """Virtual Physical Switch Model.

    This implementation works with OVS and Nexus plugin for the
    following topology:
    One or more servers to a nexus switch.
    """
    __native_bulk_support = True
    supported_extension_aliases = ["provider", "binding"]
    _methods_to_delegate = ['create_network_bulk',
                            'get_network', 'get_networks',
                            'create_port_bulk',
                            'get_port', 'get_ports',
                            'create_subnet', 'create_subnet_bulk',
                            'delete_subnet', 'update_subnet',
                            'get_subnet', 'get_subnets',
                            'create_or_update_agent', 'report_state']

    def __init__(self):
        """Initialize the segmentation manager.

        Checks which device plugins are configured, and load the inventories
        those device plugins for which the inventory is configured.
        """
        conf.CiscoConfigOptions()

        self._plugins = {}
        for key in conf.CISCO_PLUGINS.keys():
            plugin_obj = conf.CISCO_PLUGINS[key]
            if plugin_obj is not None:
                self._plugins[key] = importutils.import_object(plugin_obj)
                LOG.debug(_("Loaded device plugin %s"),
                          conf.CISCO_PLUGINS[key])

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

        # Check whether we have a valid Nexus driver loaded
        self.is_nexus_plugin = False
        nexus_driver = conf.CISCO.nexus_driver
        if nexus_driver.endswith('CiscoNEXUSDriver'):
            self.is_nexus_plugin = True

    def __getattribute__(self, name):
        """Delegate calls to OVS sub-plugin.

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
        """Get the name of the calling function."""
        frame_record = inspect.stack()[1 + offset]
        func_name = frame_record[3]
        return func_name

    def _invoke_plugin_per_device(self, plugin_key, function_name,
                                  args, **kwargs):
        """Invoke plugin per device.

        Invokes a device plugin's relevant functions (based on the
        plugin implementation) for completing this operation.
        """
        if plugin_key not in self._plugins:
            LOG.info(_("No %s Plugin loaded"), plugin_key)
            LOG.info(_("%(plugin_key)s: %(function_name)s with args %(args)s "
                     "ignored"),
                     {'plugin_key': plugin_key,
                      'function_name': function_name,
                      'args': args})
        else:
            func = getattr(self._plugins[plugin_key], function_name)
            return func(*args, **kwargs)

    def _get_segmentation_id(self, network_id):
        binding_seg_id = odb.get_network_binding(None, network_id)
        if not binding_seg_id:
            raise cexc.NetworkSegmentIDNotFound(net_id=network_id)
        return binding_seg_id.segmentation_id

    def _get_provider_vlan_id(self, network):
        if (all(attributes.is_attr_set(network.get(attr))
                for attr in (provider.NETWORK_TYPE,
                             provider.PHYSICAL_NETWORK,
                             provider.SEGMENTATION_ID))
            and
                network[provider.NETWORK_TYPE] == const.NETWORK_TYPE_VLAN):
            return network[provider.SEGMENTATION_ID]

    def create_network(self, context, network):
        """Create network.

        Perform this operation in the context of the configured device
        plugins.
        """
        LOG.debug(_("create_network() called"))
        provider_vlan_id = self._get_provider_vlan_id(network[const.NETWORK])
        args = [context, network]
        ovs_output = self._invoke_plugin_per_device(const.VSWITCH_PLUGIN,
                                                    self._func_name(),
                                                    args)
        # The vswitch plugin did all the verification. If it's a provider
        # vlan network, save it for the nexus plugin to use later.
        if provider_vlan_id:
            network_id = ovs_output[const.NET_ID]
            cdb.add_provider_network(network_id,
                                     const.NETWORK_TYPE_VLAN,
                                     provider_vlan_id)
            LOG.debug(_("Provider network added to DB: %(network_id)s, "
                        "%(vlan_id)s"),
                      {'network_id': network_id, 'vlan_id': provider_vlan_id})
        return ovs_output

    def update_network(self, context, id, network):
        """Update network.

        Perform this operation in the context of the configured device
        plugins.

        Note that the Nexus sub-plugin does not need to be notified
        (and the Nexus switch does not need to be [re]configured)
        for an update network operation because the Nexus sub-plugin
        is agnostic of all network-level attributes except the
        segmentation ID. Furthermore, updating of the segmentation ID
        is not supported by the OVS plugin since it is considered a
        provider attribute, so it is not supported by this method.
        """
        LOG.debug(_("update_network() called"))

        # We can only support updating of provider attributes if all the
        # configured sub-plugins support it. Currently we have no method
        # in place for checking whether a sub-plugin supports it,
        # so assume not.
        provider._raise_if_updates_provider_attributes(network['network'])

        args = [context, id, network]
        return self._invoke_plugin_per_device(const.VSWITCH_PLUGIN,
                                              self._func_name(),
                                              args)

    def delete_network(self, context, id):
        """Delete network.

        Perform this operation in the context of the configured device
        plugins.
        """
        args = [context, id]
        ovs_output = self._invoke_plugin_per_device(const.VSWITCH_PLUGIN,
                                                    self._func_name(),
                                                    args)
        if cdb.remove_provider_network(id):
            LOG.debug(_("Provider network removed from DB: %s"), id)
        return ovs_output

    def get_network(self, context, id, fields=None):
        """Get network. This method is delegated to the vswitch plugin.

        This method is included here to satisfy abstract method requirements.
        """
        pass  # pragma no cover

    def get_networks(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None, page_reverse=False):
        """Get networks. This method is delegated to the vswitch plugin.

        This method is included here to satisfy abstract method requirements.
        """
        pass  # pragma no cover

    def _invoke_nexus_for_net_create(self, context, tenant_id, net_id,
                                     instance_id, host_id):
        if not self.is_nexus_plugin:
            return False

        network = self.get_network(context, net_id)
        vlan_id = self._get_segmentation_id(net_id)
        vlan_name = conf.CISCO.vlan_name_prefix + str(vlan_id)
        network[const.NET_VLAN_ID] = vlan_id
        network[const.NET_VLAN_NAME] = vlan_name
        attachment = {
            const.TENANT_ID: tenant_id,
            const.INSTANCE_ID: instance_id,
            const.HOST_NAME: host_id,
        }
        self._invoke_plugin_per_device(
            const.NEXUS_PLUGIN,
            'create_network',
            [network, attachment])

    def _check_valid_port_device_owner(self, port):
        """Check the port for valid device_owner.

        Don't call the nexus plugin for router and dhcp
        port owners.
        """
        return port['device_owner'].startswith('compute')

    def _get_port_host_id_from_bindings(self, port):
        """Get host_id from portbindings."""
        host_id = None

        if (portbindings.HOST_ID in port and
            attributes.is_attr_set(port[portbindings.HOST_ID])):
            host_id = port[portbindings.HOST_ID]

        return host_id

    def create_port(self, context, port):
        """Create port.

        Perform this operation in the context of the configured device
        plugins.
        """
        LOG.debug(_("create_port() called"))
        args = [context, port]
        ovs_output = self._invoke_plugin_per_device(const.VSWITCH_PLUGIN,
                                                    self._func_name(),
                                                    args)
        instance_id = port['port']['device_id']

        # Only call nexus plugin if there's a valid instance_id, host_id
        # and device_owner
        try:
            host_id = self._get_port_host_id_from_bindings(port['port'])
            if (instance_id and host_id and
                self._check_valid_port_device_owner(port['port'])):
                net_id = port['port']['network_id']
                tenant_id = port['port']['tenant_id']
                self._invoke_nexus_for_net_create(
                    context, tenant_id, net_id, instance_id, host_id)
        except Exception:
            # Create network on the Nexus plugin has failed, so we need
            # to rollback the port creation on the VSwitch plugin.
            exc_info = sys.exc_info()
            try:
                id = ovs_output['id']
                args = [context, id]
                ovs_output = self._invoke_plugin_per_device(
                    const.VSWITCH_PLUGIN,
                    'delete_port',
                    args)
            finally:
                # Re-raise the original exception
                raise exc_info[0], exc_info[1], exc_info[2]
        return ovs_output

    def get_port(self, context, id, fields=None):
        """Get port. This method is delegated to the vswitch plugin.

        This method is included here to satisfy abstract method requirements.
        """
        pass  # pragma no cover

    def get_ports(self, context, filters=None, fields=None):
        """Get ports. This method is delegated to the vswitch plugin.

        This method is included here to satisfy abstract method requirements.
        """
        pass  # pragma no cover

    def _check_nexus_net_create_needed(self, new_port, old_port):
        """Check if nexus plugin should be invoked for net_create.

        In the following cases, the plugin should be invoked:
           -- a port is attached to a VM instance. The old host id is None
           -- VM migration. The old host id has a valid value

        When the plugin needs to be invoked, return the old_host_id,
        and a list of calling arguments.
        Otherwise, return '' for old host id and an empty list
        """
        old_device_id = old_port['device_id']
        new_device_id = new_port.get('device_id')
        new_host_id = self._get_port_host_id_from_bindings(new_port)
        tenant_id = old_port['tenant_id']
        net_id = old_port['network_id']
        old_host_id = self._get_port_host_id_from_bindings(old_port)

        LOG.debug(_("tenant_id: %(tid)s, net_id: %(nid)s, "
                    "old_device_id: %(odi)s, new_device_id: %(ndi)s, "
                    "old_host_id: %(ohi)s, new_host_id: %(nhi)s, "
                    "old_device_owner: %(odo)s, new_device_owner: %(ndo)s"),
                  {'tid': tenant_id, 'nid': net_id,
                   'odi': old_device_id, 'ndi': new_device_id,
                   'ohi': old_host_id, 'nhi': new_host_id,
                   'odo': old_port.get('device_owner'),
                   'ndo': new_port.get('device_owner')})

        # A port is attached to an instance
        if (new_device_id and not old_device_id and new_host_id and
                self._check_valid_port_device_owner(new_port)):
            return '', [tenant_id, net_id, new_device_id, new_host_id]

        # An instance is being migrated
        if (old_device_id and old_host_id and
                new_host_id and new_host_id != old_host_id and
                self._check_valid_port_device_owner(old_port)):
            return old_host_id, [tenant_id, net_id, old_device_id, new_host_id]

        # no need to invoke the plugin
        return '', []

    def update_port(self, context, id, port):
        """Update port.

        Perform this operation in the context of the configured device
        plugins.
        """
        LOG.debug(_("update_port() called"))
        old_port = self.get_port(context, id)
        args = [context, id, port]
        ovs_output = self._invoke_plugin_per_device(const.VSWITCH_PLUGIN,
                                                    self._func_name(),
                                                    args)
        try:
            # Check if the nexus plugin needs to be invoked
            old_host_id, create_args = self._check_nexus_net_create_needed(
                port['port'], old_port)

            # In the case of migration, invoke it to remove
            # the previous port binding
            if old_host_id:
                vlan_id = self._get_segmentation_id(old_port['network_id'])
                delete_args = [old_port['device_id'], vlan_id]
                self._invoke_plugin_per_device(const.NEXUS_PLUGIN,
                                               "delete_port",
                                               delete_args)

            # Invoke the Nexus plugin to create a net and/or new port binding
            if create_args:
                self._invoke_nexus_for_net_create(context, *create_args)

            return ovs_output
        except Exception:
            exc_info = sys.exc_info()
            LOG.error(_("Unable to update port '%s' on Nexus switch"),
                      old_port['name'], exc_info=exc_info)
            try:
                # Roll back vSwitch plugin to original port attributes.
                args = [context, id, {'port': old_port}]
                self._invoke_plugin_per_device(
                    const.VSWITCH_PLUGIN,
                    self._func_name(),
                    args)
            finally:
                # Re-raise the original exception
                raise exc_info[0], exc_info[1], exc_info[2]

    def delete_port(self, context, id, l3_port_check=True):
        """Delete port.

        Perform this operation in the context of the configured device
        plugins.
        """
        LOG.debug(_("delete_port() called"))
        port = self.get_port(context, id)

        host_id = self._get_port_host_id_from_bindings(port)

        if (self.is_nexus_plugin and host_id and
            self._check_valid_port_device_owner(port)):
            vlan_id = self._get_segmentation_id(port['network_id'])
            n_args = [port['device_id'], vlan_id]
            self._invoke_plugin_per_device(const.NEXUS_PLUGIN,
                                           self._func_name(),
                                           n_args)
        try:
            args = [context, id]
            ovs_output = self._invoke_plugin_per_device(
                const.VSWITCH_PLUGIN, self._func_name(),
                args, l3_port_check=l3_port_check)
        except Exception:
            exc_info = sys.exc_info()
            # Roll back the delete port on the Nexus plugin
            try:
                tenant_id = port['tenant_id']
                net_id = port['network_id']
                instance_id = port['device_id']
                host_id = port[portbindings.HOST_ID]
                self._invoke_nexus_for_net_create(context, tenant_id, net_id,
                                                  instance_id, host_id)
            finally:
                # Raise the original exception.
                raise exc_info[0], exc_info[1], exc_info[2]

        return ovs_output

    def add_router_interface(self, context, router_id, interface_info):
        """Add a router interface on a subnet.

        Only invoke the Nexus plugin to create SVI if L3 support on
        the Nexus switches is enabled and a Nexus plugin is loaded,
        otherwise send it to the vswitch plugin
        """
        if (conf.CISCO.nexus_l3_enable and self.is_nexus_plugin):
            LOG.debug(_("L3 enabled on Nexus plugin, create SVI on switch"))
            if 'subnet_id' not in interface_info:
                raise cexc.SubnetNotSpecified()
            if 'port_id' in interface_info:
                raise cexc.PortIdForNexusSvi()
            subnet = self.get_subnet(context, interface_info['subnet_id'])
            gateway_ip = subnet['gateway_ip']
            # Get gateway IP address and netmask
            cidr = subnet['cidr']
            netmask = cidr.split('/', 1)[1]
            gateway_ip = gateway_ip + '/' + netmask
            network_id = subnet['network_id']
            vlan_id = self._get_segmentation_id(network_id)
            vlan_name = conf.CISCO.vlan_name_prefix + str(vlan_id)

            n_args = [vlan_name, vlan_id, subnet['id'], gateway_ip, router_id]
            return self._invoke_plugin_per_device(const.NEXUS_PLUGIN,
                                                  self._func_name(),
                                                  n_args)
        else:
            LOG.debug(_("L3 disabled or not Nexus plugin, send to vswitch"))
            n_args = [context, router_id, interface_info]
            return self._invoke_plugin_per_device(const.VSWITCH_PLUGIN,
                                                  self._func_name(),
                                                  n_args)

    def remove_router_interface(self, context, router_id, interface_info):
        """Remove a router interface.

        Only invoke the Nexus plugin to delete SVI if L3 support on
        the Nexus switches is enabled and a Nexus plugin is loaded,
        otherwise send it to the vswitch plugin
        """
        if (conf.CISCO.nexus_l3_enable and self.is_nexus_plugin):
            LOG.debug(_("L3 enabled on Nexus plugin, delete SVI from switch"))

            subnet = self.get_subnet(context, interface_info['subnet_id'])
            network_id = subnet['network_id']
            vlan_id = self._get_segmentation_id(network_id)
            n_args = [vlan_id, router_id]

            return self._invoke_plugin_per_device(const.NEXUS_PLUGIN,
                                                  self._func_name(),
                                                  n_args)
        else:
            LOG.debug(_("L3 disabled or not Nexus plugin, send to vswitch"))
            n_args = [context, router_id, interface_info]
            return self._invoke_plugin_per_device(const.VSWITCH_PLUGIN,
                                                  self._func_name(),
                                                  n_args)

    def create_subnet(self, context, subnet):
        """Create subnet. This method is delegated to the vswitch plugin.

        This method is included here to satisfy abstract method requirements.
        """
        pass  # pragma no cover

    def update_subnet(self, context, id, subnet):
        """Update subnet. This method is delegated to the vswitch plugin.

        This method is included here to satisfy abstract method requirements.
        """
        pass  # pragma no cover

    def get_subnet(self, context, id, fields=None):
        """Get subnet. This method is delegated to the vswitch plugin.

        This method is included here to satisfy abstract method requirements.
        """
        pass  # pragma no cover

    def delete_subnet(self, context, id, kwargs):
        """Delete subnet. This method is delegated to the vswitch plugin.

        This method is included here to satisfy abstract method requirements.
        """
        pass  # pragma no cover

    def get_subnets(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None, page_reverse=False):
        """Get subnets. This method is delegated to the vswitch plugin.

        This method is included here to satisfy abstract method requirements.
        """
        pass  # pragma no cover
