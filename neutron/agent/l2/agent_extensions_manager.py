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

from oslo_log import log
import stevedore

from neutron.i18n import _LE, _LI

LOG = log.getLogger(__name__)


class AgentExtensionsManager(stevedore.named.NamedExtensionManager):
    """Manage agent extensions."""

    def __init__(self):
        # Ordered list of agent extensions, defining
        # the order in which the agent extensions are called.

        #TODO(QoS): get extensions from config
        agent_extensions = ('qos', )

        LOG.info(_LI("Configured agent extensions names: %s"),
                 agent_extensions)

        super(AgentExtensionsManager, self).__init__(
            'neutron.agent.l2.extensions', agent_extensions,
            invoke_on_load=True, name_order=True)
        LOG.info(_LI("Loaded agent extensions names: %s"), self.names())

    def initialize(self):
        # Initialize each agent extension in the list.
        for extension in self:
            LOG.info(_LI("Initializing agent extension '%s'"), extension.name)
            extension.obj.initialize()

    def handle_port(self, context, data):
        """Notify all agent extensions to handle port."""
        for extension in self:
            try:
                extension.obj.handle_port(context, data)
            # TODO(QoS) add agent extensions exception and catch them here
            except AttributeError:
                LOG.exception(
                    _LE("Agent Extension '%(name)s' failed "
                        "while handling port update"),
                    {'name': extension.name}
                )
    #TODO(Qos) we are missing how to handle delete. we can pass action
    #type in all the handle methods or add handle_delete_resource methods
