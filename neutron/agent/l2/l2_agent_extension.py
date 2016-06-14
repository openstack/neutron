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

from neutron.agent import agent_extension


@six.add_metaclass(abc.ABCMeta)
class L2AgentExtension(agent_extension.AgentExtension):
    """Define stable abstract interface for l2 agent extensions.

    An agent extension extends the agent core functionality.
    """

    def initialize(self, connection, driver_type):
        """Initialize agent extension."""

    @abc.abstractmethod
    def handle_port(self, context, data):
        """Handle agent extension for port.

        This can be called on either create or update, depending on the
        code flow. Thus, it's this function's responsibility to check what
        actually changed.

        :param context: rpc context
        :param data: port data
        """

    @abc.abstractmethod
    def delete_port(self, context, data):
        """Delete port from agent extension.

        :param context: rpc context
        :param data: port data
        """
