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

from copy import deepcopy
import inspect
import logging
import platform

from quantum.common import exceptions as exc
from quantum.common import utils
from quantum.plugins.cisco.l2network_model_base import L2NetworkModelBase
from quantum.plugins.cisco import l2network_plugin_configuration as conf
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.common import cisco_exceptions as cexc

LOG = logging.getLogger(__name__)


class L2NetworkSingleBlade(L2NetworkModelBase):
    """
    Implements the L2NetworkModelBase
    This implementation works with a single UCS blade
    """
    _plugins = {}
    _inventory = {}

    def __init__(self):
        for key in conf.PLUGINS[const.PLUGINS].keys():
            self._plugins[key] = utils.import_object(
                conf.PLUGINS[const.PLUGINS][key])
            LOG.debug("Loaded device plugin %s\n" % \
                    conf.PLUGINS[const.PLUGINS][key])
            if key in conf.PLUGINS[const.INVENTORY].keys():
                self._inventory[key] = utils.import_object(
                    conf.PLUGINS[const.INVENTORY][key])
                LOG.debug("Loaded device inventory %s\n" % \
                        conf.PLUGINS[const.INVENTORY][key])

    def _func_name(self, offset=0):
        """Get the name of the calling function"""
        return inspect.stack()[1 + offset][3]

    def _invoke_plugin_per_device(self, plugin_key, function_name, args):
        """Invoke only device plugin for all the devices in the system"""
        if not plugin_key in self._plugins.keys():
            LOG.info("No %s Plugin loaded" % plugin_key)
            LOG.info("%s: %s with args %s ignored" \
                     % (plugin_key, function_name, args))
            return
        device_params = self._invoke_inventory(plugin_key, function_name,
                                               args)
        device_ips = device_params[const.DEVICE_IP]
        if not device_ips:
            self._invoke_plugin(plugin_key, function_name, args,
                                device_params)
        else:
            for device_ip in device_ips:
                new_device_params = deepcopy(device_params)
                new_device_params[const.DEVICE_IP] = device_ip
                self._invoke_plugin(plugin_key, function_name, args,
                                    new_device_params)

    def _invoke_inventory(self, plugin_key, function_name, args):
        """Invoke only the inventory implementation"""
        if not plugin_key in self._inventory.keys():
            LOG.warn("No %s inventory loaded" % plugin_key)
            LOG.warn("%s: %s with args %s ignored" \
                     % (plugin_key, function_name, args))
            return {const.DEVICE_IP: []}
        else:
            return getattr(self._inventory[plugin_key], function_name)(args)

    def _invoke_plugin(self, plugin_key, function_name, args, kwargs):
        """Invoke only the device plugin"""
        # If the last param is a dict, add it to kwargs
        if args and isinstance(args[-1], dict):
            kwargs.update(args.pop())

        return getattr(self._plugins[plugin_key], function_name)(*args,
                                                                 **kwargs)

    def get_all_networks(self, args):
        """Not implemented for this model"""
        pass

    def create_network(self, args):
        """Support for the Quantum core API call"""
        self._invoke_plugin_per_device(const.UCS_PLUGIN, self._func_name(),
                                       args)

    def delete_network(self, args):
        """Support for the Quantum core API call"""
        self._invoke_plugin_per_device(const.UCS_PLUGIN, self._func_name(),
                                       args)

    def get_network_details(self, args):
        """Not implemented for this model"""
        pass

    def update_network(self, args):
        """Support for the Quantum core API call"""
        self._invoke_plugin_per_device(const.UCS_PLUGIN, self._func_name(),
                                       args)

    def get_all_ports(self, args):
        """Not implemented for this model"""
        pass

    def create_port(self, args):
        """Support for the Quantum core API call"""
        self._invoke_plugin_per_device(const.UCS_PLUGIN, self._func_name(),
                                       args)

    def delete_port(self, args):
        """Support for the Quantum core API call"""
        self._invoke_plugin_per_device(const.UCS_PLUGIN, self._func_name(),
                                       args)

    def update_port(self, args):
        """Not implemented for this model"""
        pass

    def get_port_details(self, args):
        """Not implemented for this model"""
        pass

    def plug_interface(self, args):
        """Support for the Quantum core API call"""
        self._invoke_plugin_per_device(const.UCS_PLUGIN, self._func_name(),
                                       args)

    def unplug_interface(self, args):
        """Support for the Quantum core API call"""
        self._invoke_plugin_per_device(const.UCS_PLUGIN, self._func_name(),
                                       args)

    def schedule_host(self, args):
        """Provides the hostname on which a dynamic vnic is reserved"""
        LOG.debug("schedule_host() called\n")
        return self._invoke_inventory(const.UCS_PLUGIN, self._func_name(),
                                      args)

    def associate_port(self, args):
        """
        Get the portprofile name and the device namei for the dynamic vnic
        """
        LOG.debug("associate_port() called\n")
        return self._invoke_inventory(const.UCS_PLUGIN, self._func_name(),
                                      args)

    def detach_port(self, args):
        """
        Remove the association of the VIF with the dynamic vnic
        """
        LOG.debug("detach_port() called\n")
        return self._invoke_plugin_per_device(const.UCS_PLUGIN,
                                              self._func_name(), args)

    def create_multiport(self, args):
        """Support for extension  API call"""
        self._invoke_plugin_per_device(const.UCS_PLUGIN, self._func_name(),
                                       args)
