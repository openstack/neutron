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
    """Define stable abstract interface for agent extensions.

    An agent extension extends the agent core functionality.
    """

    def initialize(self, connection, driver_type):
        """Perform agent core resource extension initialization.

        :param connection: RPC connection that can be reused by the extension
                           to define its RPC endpoints
        :param driver_type: a string that defines the agent type to the
                            extension. Can be used to choose the right backend
                            implementation.

        Called after all extensions have been loaded.
        No port handling will be called before this method.
        """

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
