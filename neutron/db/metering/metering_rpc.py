# Copyright (C) 2014 eNovance SAS <licensing@enovance.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from neutron_lib.api import extensions
from neutron_lib import constants as consts
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_log import log as logging
import oslo_messaging


LOG = logging.getLogger(__name__)


class MeteringRpcCallbacks:

    target = oslo_messaging.Target(version='1.0')

    def __init__(self, meter_plugin):
        self.meter_plugin = meter_plugin

    def get_sync_data_metering(self, context, **kwargs):
        l3_plugin = directory.get_plugin(plugin_constants.L3)
        if not l3_plugin:
            return

        metering_data = self.meter_plugin.get_sync_data_metering(context)
        host = kwargs.get('host')
        if not extensions.is_extension_supported(
                l3_plugin, consts.L3_AGENT_SCHEDULER_EXT_ALIAS) or not host:
            return metering_data
        agents = l3_plugin.get_l3_agents(context, filters={'host': [host]})
        if not agents:
            LOG.error('Unable to find agent on host %s.', host)
            return

        router_ids = []
        for agent in agents:
            routers = l3_plugin.list_routers_on_l3_agent(context, agent.id)
            router_ids += [router['id'] for router in routers['routers']]
        if not router_ids:
            return
        return [
            router for router in metering_data
            if router['id'] in router_ids
        ]
