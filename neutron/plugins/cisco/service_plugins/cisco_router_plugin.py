# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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

import oslo_messaging

from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.db import agents_db
from neutron.db import common_db_mixin
from neutron import manager
from neutron.plugins.cisco.db.l3 import device_handling_db
from neutron.plugins.cisco.db.l3 import l3_router_appliance_db
from neutron.plugins.cisco.l3.rpc import (l3_router_cfgagent_rpc_cb as
                                          l3_router_rpc)
from neutron.plugins.cisco.l3.rpc import devices_cfgagent_rpc_cb as devices_rpc
from neutron.plugins.common import constants


class CiscoRouterPluginRpcCallbacks(l3_router_rpc.L3RouterCfgRpcCallbackMixin,
                                    devices_rpc.DeviceCfgRpcCallbackMixin):

    target = oslo_messaging.Target(version='1.1')

    def __init__(self, l3plugin):
        super(CiscoRouterPluginRpcCallbacks, self).__init__()
        self._l3plugin = l3plugin

    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()


class CiscoRouterPlugin(common_db_mixin.CommonDbMixin,
                        agents_db.AgentDbMixin,
                        l3_router_appliance_db.L3RouterApplianceDBMixin,
                        device_handling_db.DeviceHandlingMixin):

    """Implementation of Cisco L3 Router Service Plugin for Neutron.

    This class implements a L3 service plugin that provides
    router and floatingip resources and manages associated
    request/response.
    All DB functionality is implemented in class
    l3_router_appliance_db.L3RouterApplianceDBMixin.
    """
    supported_extension_aliases = ["router", "extraroute"]

    def __init__(self):
        self.setup_rpc()
        # for backlogging of non-scheduled routers
        self._setup_backlog_handling()
        self._setup_device_handling()

    def setup_rpc(self):
        # RPC support
        self.topic = topics.L3PLUGIN
        self.conn = n_rpc.create_connection(new=True)
        self.endpoints = [CiscoRouterPluginRpcCallbacks(self)]
        self.conn.create_consumer(self.topic, self.endpoints,
                                  fanout=False)
        # Consume from all consumers in threads
        self.conn.consume_in_threads()

    def get_plugin_type(self):
        return constants.L3_ROUTER_NAT

    def get_plugin_description(self):
        return ("Cisco Router Service Plugin for basic L3 forwarding"
                " between (L2) Neutron networks and access to external"
                " networks via a NAT gateway.")

    @property
    def _core_plugin(self):
        try:
            return self._plugin
        except AttributeError:
            self._plugin = manager.NeutronManager.get_plugin()
            return self._plugin
