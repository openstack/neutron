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

import abc

import six

from neutron.agent import agent_extension


@six.add_metaclass(abc.ABCMeta)
class L3AgentCoreResourceExtension(agent_extension.AgentExtension):
    """Define stable abstract interface for l3 agent extensions.

    An agent extension extends the agent core functionality.
    """

    @abc.abstractmethod
    def add_router(self, context, data):
        """add agent extension for router.

        Called on router create.

        :param context: rpc context
        :param data: router data
        """

    @abc.abstractmethod
    def update_router(self, context, data):
        """Handle agent extension for update.

        Called on router update.

        :param context: rpc context
        :param data: router data
        """

    @abc.abstractmethod
    def delete_router(self, context, data):
        """Delete router from agent extension.

        :param context: rpc context
        :param data: router data
        """

    @abc.abstractmethod
    def ha_state_change(self, context, data):
        """Change router state from agent extension.

        Called on HA router state change.

        :param context: rpc context
        :param data: dict of router_id and new state
        """
