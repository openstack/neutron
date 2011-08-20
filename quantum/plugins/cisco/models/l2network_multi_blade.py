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
import logging as LOG

from quantum.common import utils
from quantum.plugins.cisco.l2network_model_base import L2NetworkModelBase
from quantum.plugins.cisco import l2network_plugin_configuration as conf
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.ucs import cisco_ucs_inventory as ucsinv 

LOG.basicConfig(level=LOG.WARN)
LOG.getLogger(const.LOGGER_COMPONENT_NAME)


class L2NetworkMultiBlade(L2NetworkModelBase):
    """
    Implements the L2NetworkModelBase
    This implementation works with UCS and Nexus plugin for the
    following topology:
    One or more UCSM (each with one or more chasses connected)
    All UCSM connected to a single Nexus Switch
    """
    _plugins = {}

    def __init__(self):
        for key in conf.PLUGINS[const.PLUGINS].keys():
            self._plugins[key] = utils.import_object(
                conf.PLUGINS[const.PLUGINS][key])
            LOG.debug("Loaded device plugin %s\n" % \
                    conf.PLUGINS[const.PLUGINS][key])

        self._ucs_inventory = ucsinv.UCSInventory()

    def _func_name(self, offset=0):
        """Get the name of the calling function"""
        return inspect.stack()[1 + offset][3]

    def _invoke_all_device_plugins(self, function_name, args, kwargs):
        """Invoke all device plugins for this model implementation"""
        for plugin_obj_ref in self._plugins.values():
            getattr(plugin_obj_ref, function_name)(*args, **kwargs)

    def _invoke_ucs_plugin(self, function_name, args, kwargs):
        """Invoke only the UCS plugin"""
        if const.UCS_PLUGIN in self._plugins.keys():
            getattr(self._plugins[const.UCS_PLUGIN],
                    function_name)(*args, **kwargs)

    def _invoke_ucs_plugin_per_device(self, function_name, args):
        """Invoke only UCS plugin for all the UCSMs in the system"""
        ucsm_ips = self._ucs_inventory.get_all_ucsms()
        for ucsm_ip in ucsm_ips:
            device_params = {const.DEVICE_IP: ucsm_ip}
            self._invoke_ucs_plugin(function_name, args, device_params)

    def _invoke_nexus_plugin(self, function_name, args, kwargs):
        """Invoke only the Nexus plugin"""
        if const.NEXUS_PLUGIN in self._plugins.keys():
            getattr(self._plugins[const.NEXUS_PLUGIN],
                    function_name)(*args, **kwargs)

    def _invoke_nexus_plugin_per_device(self, function_name, args):
        """Invoke only the nexus plugin for all the switches in the system"""
        device_params = {const.DEVICE_IP: ""}
        self._invoke_nexus_plugin(self._func_name(), args, device_params)

    def get_all_networks(self, args):
        """Not implemented for this model"""
        pass

    def create_network(self, args):
        """Support for the Quantum core API call"""
        self._invoke_ucs_plugin_per_device(self._func_name(), args)
        self._invoke_nexus_plugin_per_device(self._func_name(), args)

    def delete_network(self, args):
        """Support for the Quantum core API call"""
        self._invoke_ucs_plugin_per_device(self._func_name(), args)
        self._invoke_nexus_plugin_per_device(self._func_name(), args)

    def get_network_details(self, args):
        """Not implemented for this model"""
        pass

    def rename_network(self, args):
        """Support for the Quantum core API call"""
        self._invoke_ucs_plugin_per_device(self._func_name(), args)
        self._invoke_nexus_plugin_per_device(self._func_name(), args)

    def get_all_ports(self, args):
        """Not implemented for this model"""
        pass

    def create_port(self, args):
        """Support for the Quantum core API call"""
        least_reserved_blade_dict = \
                self._ucs_inventory.get_least_reserved_blade()
        ucsm_ip = least_reserved_blade_dict[const.LEAST_RSVD_BLADE_UCSM]
        device_params = {const.DEVICE_IP: ucsm_ip,
                         const.UCS_INVENTORY: self._ucs_inventory,
                         const.LEAST_RSVD_BLADE_DICT:\
                         least_reserved_blade_dict}
        self._invoke_ucs_plugin(self._func_name(), args, device_params)

    def delete_port(self, args):
        """Support for the Quantum core API call"""
        rsvd_info = \
                self._ucs_inventory.get_rsvd_blade_intf_by_port(args[0],
                                                                args[2])
        device_params = \
                {const.DEVICE_IP: rsvd_info[const.UCSM_IP],
                 const.UCS_INVENTORY: self._ucs_inventory,
                 const.CHASSIS_ID: rsvd_info[const.const.CHASSIS_ID],
                 const.BLADE_ID: rsvd_info[const.const.BLADE_ID],
                 const.BLADE_INTF_DN: rsvd_info[const.BLADE_INTF_DN]}
        self._invoke_ucs_plugin(self._func_name(), args, device_params)

    def update_port(self, args):
        """Not implemented for this model"""
        pass

    def get_port_details(self, args):
        """Not implemented for this model"""
        pass

    def plug_interface(self, args):
        """Support for the Quantum core API call"""
        device_params = {const.DEVICE_IP: ""}
        self._invoke_ucs_plugin(self._func_name(), args, device_params)

    def unplug_interface(self, args):
        """Support for the Quantum core API call"""
        device_params = {const.DEVICE_IP: ""}
        self._invoke_ucs_plugin(self._func_name(), args, device_params)

    def get_host(self, args):
        """Provides the hostname on which a dynamic vnic is reserved"""
        LOG.debug("get_host() called\n")
        host_list = {const.HOST_LIST: {const.HOST_1: platform.node()}}
        return host_list

    def get_instance_port(self, args):
        """
        Get the portprofile name and the device namei for the dynamic vnic
        """
        LOG.debug("get_instance_port() called\n")
        vif_desc = {const.VIF_DESC:
                    {const.DEVICENAME: "eth2", const.UCSPROFILE: "default"}}
        return vif_desc

