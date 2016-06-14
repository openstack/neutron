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

import abc

import six


@six.add_metaclass(abc.ABCMeta)
class AgentExtension(object):
    """Define stable abstract interface for agent extensions.

    An agent extension extends the agent core functionality.
    """

    @abc.abstractmethod
    def initialize(self, connection, driver_type):
        """Perform agent core resource extension initialization.

        :param connection: RPC connection that can be reused by the extension
                           to define its RPC endpoints
        :param driver_type: a string that defines the agent type to the
                            extension. Can be used to choose the right backend
                            implementation.

        Called after all extensions have been loaded.
        No resource (port, policy, router, etc.) handling will be called before
        this method.
        """

    def consume_api(self, agent_api):
        """Consume the AgentAPI instance from the AgentExtensionsManager.

        Allows an extension to gain access to resources internal to the
        neutron agent and otherwise unavailable to the extension.  Examples of
        such resources include bridges, ports, and routers.

        :param agent_api: An instance of an agent-specific API.
        """
