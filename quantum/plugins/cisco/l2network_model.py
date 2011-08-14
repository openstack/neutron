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

from quantum.common import utils
from quantum.plugins.cisco.l2network_model_base import L2NetworkModelBase
from quantum.plugins.cisco import l2network_plugin_configuration as conf
from quantum.plugins.cisco.common import cisco_constants as const

LOG.basicConfig(level=LOG.WARN)
LOG.getLogger(const.LOGGER_COMPONENT_NAME)


class L2NetworkModel(L2NetworkModelBase):
    _plugins = {}

    def __init__(self):
        for key in conf.plugins[const.PLUGINS].keys():
            self._plugins[key] = utils.import_object(
                conf.plugins[const.PLUGINS][key])
            LOG.debug("Loaded device plugin %s\n" % \
                    conf.plugins[const.PLUGINS][key])

    def _funcName(self, offset=0):
        return inspect.stack()[1 + offset][3]

    def _invokeAllDevicePlugins(self, function_name, args, kwargs):
        for pluginObjRef in self._plugins.values():
            getattr(pluginObjRef, function_name)(*args, **kwargs)

    def _invokeUCSPlugin(self, function_name, args, kwargs):
        if const.UCS_PLUGIN in self._plugins.keys():
            getattr(self._plugins[const.UCS_PLUGIN],
                    function_name)(*args, **kwargs)

    def _invokeNexusPlugin(self, function_name, args, kwargs):
        if const.NEXUS_PLUGIN in self._plugins.keys():
            getattr(self._plugins[const.NEXUS_PLUGIN],
                    function_name)(*args, **kwargs)

    def get_all_networks(self, args):
        pass

    def create_network(self, args):
        deviceParams = {const.DEVICE_IP: ""}
        self._invokeAllDevicePlugins(self._funcName(), args, deviceParams)

    def delete_network(self, args):
        deviceParams = {const.DEVICE_IP: ""}
        self._invokeAllDevicePlugins(self._funcName(), args, deviceParams)

    def get_network_details(self, args):
        pass

    def rename_network(self, args):
        deviceParams = {const.DEVICE_IP: ""}
        self._invokeAllDevicePlugins(self._funcName(), args, deviceParams)

    def get_all_ports(self, args):
        pass

    def create_port(self, args):
        deviceParams = {const.DEVICE_IP: ""}
        self._invokeUCSPlugin(self._funcName(), args, deviceParams)

    def delete_port(self, args):
        deviceParams = {const.DEVICE_IP: ""}
        self._invokeUCSPlugin(self._funcName(), args, deviceParams)

    def update_port(self, args):
        pass

    def get_port_details(self, args):
        pass

    def plug_interface(self, args):
        deviceParams = {const.DEVICE_IP: ""}
        self._invokeUCSPlugin(self._funcName(), args, deviceParams)

    def unplug_interface(self, args):
        deviceParams = {const.DEVICE_IP: ""}
        self._invokeUCSPlugin(self._funcName(), args, deviceParams)
