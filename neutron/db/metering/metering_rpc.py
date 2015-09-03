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

from oslo_log import log as logging
import oslo_messaging

from neutron.common import constants as consts
from neutron.common import utils
from neutron.i18n import _LE
from neutron import manager
from neutron.plugins.common import constants as service_constants

LOG = logging.getLogger(__name__)


class MeteringRpcCallbacks(object):

    target = oslo_messaging.Target(version='1.0')

    def __init__(self, meter_plugin):
        self.meter_plugin = meter_plugin

    def get_sync_data_metering(self, context, **kwargs):
        l3_plugin = manager.NeutronManager.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)
        if not l3_plugin:
            return

        host = kwargs.get('host')
        if not utils.is_extension_supported(
            l3_plugin, consts.L3_AGENT_SCHEDULER_EXT_ALIAS) or not host:
            return self.meter_plugin.get_sync_data_metering(context)
        else:
            agents = l3_plugin.get_l3_agents(context, filters={'host': [host]})
            if not agents:
                LOG.error(_LE('Unable to find agent %s.'), host)
                return

            routers = l3_plugin.list_routers_on_l3_agent(context, agents[0].id)
            router_ids = [router['id'] for router in routers['routers']]
            if not router_ids:
                return

        return self.meter_plugin.get_sync_data_metering(context,
                                                        router_ids=router_ids)
