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

import abc

import six


@six.add_metaclass(abc.ABCMeta)
class AgentCoreResourceExtension(object):
    """Define stable abstract interface for Agent extension.

    An agent extension extends the agent core functionality.
    """

    def initialize(self, resource_rpc):
        """Perform agent core resource extension initialization.

        Called after all extensions have been loaded.
        No abstract methods defined below will be
        called prior to this method being called.
        :param resource_rpc - the agent side rpc for getting
        resource by type and id
        """
        self.resource_rpc = resource_rpc

    def handle_network(self, context, data):
        """handle agent extension for network.

        :param context - rpc context
        :param data - network data
        """
        pass

    def handle_subnet(self, context, data):
        """handle agent extension for subnet.

        :param context - rpc context
        :param data - subnet data
        """
        pass

    def handle_port(self, context, data):
        """handle agent extension for port.

        :param context - rpc context
        :param data - port data
        """
        pass
