# Copyright (c) 2013 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import abc

from neutron_lib.api.definitions import agent as apidef
from neutron_lib.api import extensions as api_extensions
from neutron_lib import exceptions
from neutron_lib.plugins import directory
import six

from neutron.api import extensions
from neutron.api.v2 import base


class Agent(api_extensions.APIExtensionDescriptor):
    """Agent management extension."""

    api_definition = apidef

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plugin = directory.get_plugin()
        params = apidef.RESOURCE_ATTRIBUTE_MAP.get(apidef.COLLECTION_NAME)
        controller = base.create_resource(apidef.COLLECTION_NAME,
                                          apidef.RESOURCE_NAME,
                                          plugin, params)

        ex = extensions.ResourceExtension(apidef.COLLECTION_NAME,
                                          controller)

        return [ex]


@six.add_metaclass(abc.ABCMeta)
class AgentPluginBase(object):
    """REST API to operate the Agent.

    All of method must be in an admin context.
    """

    def create_agent(self, context, agent):
        """Create agent.

        This operation is not allow in REST API.
        @raise exceptions.BadRequest:
        """
        raise exceptions.BadRequest()

    @abc.abstractmethod
    def delete_agent(self, context, id):
        """Delete agent.

        Agents register themselves on reporting state.
        But if an agent does not report its status
        for a long time (for example, it is dead forever. ),
        admin can remove it. Agents must be disabled before
        being removed.
        """
        pass

    @abc.abstractmethod
    def update_agent(self, context, agent):
        """Disable or Enable the agent.

        Description also can be updated. Some agents cannot be disabled, such
        as plugins, services. An error code should be reported in this case.
        @raise exceptions.BadRequest:
        """
        pass

    @abc.abstractmethod
    def get_agents(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_agent(self, context, id, fields=None):
        pass
