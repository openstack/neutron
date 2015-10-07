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

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import base
from neutron.common import exceptions
from neutron import manager


# Attribute Map
RESOURCE_NAME = 'agent'
RESOURCE_ATTRIBUTE_MAP = {
    RESOURCE_NAME + 's': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True},
        'agent_type': {'allow_post': False, 'allow_put': False,
                       'is_visible': True},
        'binary': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'topic': {'allow_post': False, 'allow_put': False,
                  'is_visible': True},
        'host': {'allow_post': False, 'allow_put': False,
                 'is_visible': True},
        'admin_state_up': {'allow_post': False, 'allow_put': True,
                           'convert_to': attr.convert_to_boolean,
                           'is_visible': True},
        'created_at': {'allow_post': False, 'allow_put': False,
                       'is_visible': True},
        'started_at': {'allow_post': False, 'allow_put': False,
                       'is_visible': True},
        'heartbeat_timestamp': {'allow_post': False, 'allow_put': False,
                                'is_visible': True},
        'alive': {'allow_post': False, 'allow_put': False,
                  'is_visible': True},
        'configurations': {'allow_post': False, 'allow_put': False,
                           'is_visible': True},
        'description': {'allow_post': False, 'allow_put': True,
                        'is_visible': True,
                        'validate': {
                            'type:string_or_none': attr.DESCRIPTION_MAX_LEN}},
    },
}


class AgentNotFound(exceptions.NotFound):
    message = _("Agent %(id)s could not be found")


class AgentNotFoundByTypeHost(exceptions.NotFound):
    message = _("Agent with agent_type=%(agent_type)s and host=%(host)s "
                "could not be found")


class MultipleAgentFoundByTypeHost(exceptions.Conflict):
    message = _("Multiple agents with agent_type=%(agent_type)s and "
                "host=%(host)s found")


class Agent(object):
    """Agent management extension."""

    @classmethod
    def get_name(cls):
        return "agent"

    @classmethod
    def get_alias(cls):
        return "agent"

    @classmethod
    def get_description(cls):
        return "The agent management extension."

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/agent/api/v2.0"

    @classmethod
    def get_updated(cls):
        return "2013-02-03T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        my_plurals = [(key, key[:-1]) for key in RESOURCE_ATTRIBUTE_MAP.keys()]
        attr.PLURALS.update(dict(my_plurals))
        plugin = manager.NeutronManager.get_plugin()
        params = RESOURCE_ATTRIBUTE_MAP.get(RESOURCE_NAME + 's')
        controller = base.create_resource(RESOURCE_NAME + 's',
                                          RESOURCE_NAME,
                                          plugin, params
                                          )

        ex = extensions.ResourceExtension(RESOURCE_NAME + 's',
                                          controller)

        return [ex]

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


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
        But if a agent does not report its status
        for a long time (for example, it is dead for ever. ),
        admin can remove it. Agents must be disabled before
        being removed.
        """
        pass

    @abc.abstractmethod
    def update_agent(self, context, agent):
        """Disable or Enable the agent.

        Discription also can be updated. Some agents cannot be disabled, such
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
