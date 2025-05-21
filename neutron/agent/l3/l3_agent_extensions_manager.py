# Copyright (c) 2015 Mellanox Technologies, Ltd
# All Rights Reserved.
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

from neutron_lib.agent import l3_extension
from neutron_lib.exceptions import l3 as l3_exc
from oslo_log import log

from neutron.agent import agent_extensions_manager as agent_ext_manager
from neutron.conf.agent import agent_extensions_manager as agent_ext_mgr_config

LOG = log.getLogger(__name__)


L3_AGENT_EXT_MANAGER_NAMESPACE = 'neutron.agent.l3.extensions'


def register_opts(conf):
    agent_ext_mgr_config.register_agent_ext_manager_opts(conf)


class L3AgentExtensionsManager(agent_ext_manager.AgentExtensionsManager):
    """Manage l3 agent extensions."""

    def __init__(self, conf):
        super().__init__(conf, L3_AGENT_EXT_MANAGER_NAMESPACE)
        extensions = []
        for extension in self:
            if not isinstance(extension.obj, l3_extension.L3AgentExtension):
                extensions.append(extension.attr)
        if extensions:
            raise l3_exc.L3ExtensionException(extensions=extensions)

    def add_router(self, context, data):
        """Notify all agent extensions to add router."""
        for extension in self:
            extension.obj.add_router(context, data)
        LOG.debug("L3 agent extension(s) finished router %s "
                  "add action.", data['id'])

    def update_router(self, context, data):
        """Notify all agent extensions to update router."""
        for extension in self:
            extension.obj.update_router(context, data)
        LOG.debug("L3 agent extension(s) finished router %s "
                  "update action.", data['id'])

    def delete_router(self, context, data):
        """Notify all agent extensions to delete router."""
        for extension in self:
            extension.obj.delete_router(context, data)
        LOG.debug("L3 agent extension(s) finished router %s "
                  "delete action.", data['id'])

    def ha_state_change(self, context, data):
        """Notify all agent extensions for HA router state change."""
        for extension in self:
            extension.obj.ha_state_change(context, data)
        LOG.debug('L3 agent extension(s) finished HA state change to "%s" '
                  'for router %s', data['state'], data['router_id'])
