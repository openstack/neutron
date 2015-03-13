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

import inspect

from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import importutils

from neutron.api.v2 import attributes
from neutron.extensions import portbindings
from neutron.extensions import providernet as provider
from neutron.i18n import _LE, _LI
from neutron import neutron_plugin_base_v2
from neutron.plugins.cisco.common import cisco_constants as const
from neutron.plugins.cisco.common import cisco_credentials_v2 as cred
from neutron.plugins.cisco.common import config as conf
from neutron.plugins.cisco.db import network_db_v2 as cdb


LOG = logging.getLogger(__name__)


class VirtualPhysicalSwitchModelV2(neutron_plugin_base_v2.NeutronPluginBaseV2):
    """Virtual Physical Switch Model.

    This implementation works with n1kv sub-plugin for the
    following topology:
    One or more servers to a n1kv switch.
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
        self._plugins['vswitch_plugin'] = importutils.import_object(
            'neutron.plugins.cisco.n1kv.n1kv_neutron_plugin.'
            'N1kvNeutronPluginV2')

        if ((const.VSWITCH_PLUGIN in self._plugins) and
            hasattr(self._plugins[const.VSWITCH_PLUGIN],
                    "supported_extension_aliases")):
            self.supported_extension_aliases.extend(
                self._plugins[const.VSWITCH_PLUGIN].
                supported_extension_aliases)

        # Initialize credential store after database initialization
        cred.Store.initialize()
        LOG.debug("%(module)s.%(name)s init done",
                  {'module': __name__,
                   'name': self.__class__.__name__})

    def __getattribute__(self, name):
        """Delegate calls to sub-plugin.

        This delegates the calls to the methods implemented by the
        sub-plugin. Note: Currently, bulking is handled by the caller
        (PluginV2), and this model class expects to receive only non-bulking
        calls. If, however, a bulking call is made, this will method will
        delegate the call to the sub-plugin.
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
            LOG.info(_LI("No %s Plugin loaded"), plugin_key)
            LOG.info(_LI("%(plugin_key)s: %(function_name)s with args "
                         "%(args)s ignored"),
                     {'plugin_key': plugin_key,
                      'function_name': function_name,
                      'args': args})
        else:
            func = getattr(self._plugins[plugin_key], function_name)
            return func(*args, **kwargs)

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
        LOG.debug("create_network() called")
        provider_vlan_id = self._get_provider_vlan_id(network[const.NETWORK])
        args = [context, network]
        switch_output = self._invoke_plugin_per_device(const.VSWITCH_PLUGIN,
                                                       self._func_name(),
                                                       args)
        # The vswitch plugin did all the verification. If it's a provider
        # vlan network, save it for the sub-plugin to use later.
        if provider_vlan_id:
            network_id = switch_output[const.NET_ID]
            cdb.add_provider_network(network_id,
                                     const.NETWORK_TYPE_VLAN,
                                     provider_vlan_id)
            LOG.debug("Provider network added to DB: %(network_id)s, "
                      "%(vlan_id)s",
                      {'network_id': network_id, 'vlan_id': provider_vlan_id})
        return switch_output

    def update_network(self, context, id, network):
        """Update network.

        Perform this operation in the context of the configured device
        plugins.
        """
        LOG.debug("update_network() called")

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
        switch_output = self._invoke_plugin_per_device(const.VSWITCH_PLUGIN,
                                                       self._func_name(),
                                                       args)
        if cdb.remove_provider_network(id):
            LOG.debug("Provider network removed from DB: %s", id)
        return switch_output

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

    def _check_valid_port_device_owner(self, port):
        """Check the port for valid device_owner.

        Don't call the sub-plugin for router and dhcp
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
        LOG.debug("create_port() called")
        args = [context, port]
        return self._invoke_plugin_per_device(const.VSWITCH_PLUGIN,
                                              self._func_name(),
                                              args)

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

    def update_port(self, context, id, port):
        """Update port.

        Perform this operation in the context of the configured device
        plugins.
        """
        LOG.debug("update_port() called")
        args = [context, id, port]
        return self._invoke_plugin_per_device(const.VSWITCH_PLUGIN,
                                              self._func_name(),
                                              args)

    def delete_port(self, context, id, l3_port_check=True):
        """Delete port.

        Perform this operation in the context of the configured device
        plugins.
        """
        LOG.debug("delete_port() called")
        port = self.get_port(context, id)

        try:
            args = [context, id]
            switch_output = self._invoke_plugin_per_device(
                const.VSWITCH_PLUGIN, self._func_name(),
                args, l3_port_check=l3_port_check)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Unable to delete port '%(pname)s' on switch. "
                              "Exception: %(exp)s"), {'pname': port['name'],
                                                      'exp': e})

        return switch_output

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
