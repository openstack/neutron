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

from oslo_config import cfg
from oslo_log import log
import stevedore

from neutron.i18n import _LE, _LI

LOG = log.getLogger(__name__)


L2_AGENT_EXT_MANAGER_NAMESPACE = 'neutron.agent.l2.extensions'
L2_AGENT_EXT_MANAGER_OPTS = [
    cfg.ListOpt('extensions',
                default=[],
                help=_('Extensions list to use')),
]


def register_opts(conf):
    conf.register_opts(L2_AGENT_EXT_MANAGER_OPTS, 'agent')


class AgentExtensionsManager(stevedore.named.NamedExtensionManager):
    """Manage agent extensions."""

    def __init__(self, conf):
        super(AgentExtensionsManager, self).__init__(
            L2_AGENT_EXT_MANAGER_NAMESPACE, conf.agent.extensions,
            invoke_on_load=True, name_order=True)
        LOG.info(_LI("Loaded agent extensions: %s"), self.names())

    def initialize(self, connection):
        # Initialize each agent extension in the list.
        for extension in self:
            LOG.info(_LI("Initializing agent extension '%s'"), extension.name)
            extension.obj.initialize(connection)

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
