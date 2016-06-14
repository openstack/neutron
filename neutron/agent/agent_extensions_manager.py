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

from oslo_config import cfg
from oslo_log import log
import stevedore

from neutron._i18n import _, _LI

LOG = log.getLogger(__name__)


AGENT_EXT_MANAGER_OPTS = [
    cfg.ListOpt('extensions',
                default=[],
                help=_('Extensions list to use')),
]


def register_opts(conf):
    conf.register_opts(AGENT_EXT_MANAGER_OPTS, 'agent')


class AgentExtensionsManager(stevedore.named.NamedExtensionManager):
    """Manage agent extensions."""

    def __init__(self, conf, namespace):
        super(AgentExtensionsManager, self).__init__(
            namespace, conf.agent.extensions,
            invoke_on_load=True, name_order=True)
        LOG.info(_LI("Loaded agent extensions: %s"), self.names())

    def initialize(self, connection, driver_type, agent_api=None):
        """Initialize enabled agent extensions.

        :param connection: RPC connection that can be reused by extensions to
                           define their RPC endpoints
        :param driver_type: a string that defines the agent type to the
                            extension. Can be used by the extension to choose
                            the right backend implementation.
        :param agent_api: an AgentAPI instance that provides an API to
                          interact with the agent that the manager
                          is running in.
        """
        # Initialize each agent extension in the list.
        for extension in self:
            LOG.info(_LI("Initializing agent extension '%s'"), extension.name)
            # If the agent has provided an agent_api object, this object will
            # be passed to all interested extensions.  This object must be
            # consumed by each such extension before the extension's
            # intialize() method is called, as the initilization step
            # relies on the agent_api already being available.

            extension.obj.consume_api(agent_api)
            extension.obj.initialize(connection, driver_type)
