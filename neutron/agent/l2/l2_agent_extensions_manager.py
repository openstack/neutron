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

from oslo_log import log

from neutron.agent import agent_extensions_manager as agent_ext_manager
from neutron.conf.agent import agent_extensions_manager as agent_ext_mgr_config

LOG = log.getLogger(__name__)


L2_AGENT_EXT_MANAGER_NAMESPACE = 'neutron.agent.l2.extensions'


def register_opts(conf):
    agent_ext_mgr_config.register_agent_ext_manager_opts(conf)


class L2AgentExtensionsManager(agent_ext_manager.AgentExtensionsManager):
    """Manage l2 agent extensions. The handle_port and delete_port methods are
       guaranteed to be attributes of each extension because they have been
       marked as abc.abstractmethod in the extensions' abstract class.
    """

    def __init__(self, conf):
        super().__init__(conf, L2_AGENT_EXT_MANAGER_NAMESPACE)

    def handle_port(self, context, data):
        """Notify all agent extensions to handle port."""
        for extension in self:
            if hasattr(extension.obj, 'handle_port'):
                extension.obj.handle_port(context, data)
            else:
                LOG.error(
                    "Agent Extension '%(name)s' does not "
                    "implement method handle_port",
                    {'name': extension.name}
                )

    def delete_port(self, context, data):
        """Notify all agent extensions to delete port."""
        for extension in self:
            if hasattr(extension.obj, 'delete_port'):
                extension.obj.delete_port(context, data)
            else:
                LOG.error(
                    "Agent Extension '%(name)s' does not "
                    "implement method delete_port",
                    {'name': extension.name}
                )
