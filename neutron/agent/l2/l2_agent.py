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

from neutron.agent.l2 import agent_extensions_manager


#TODO(QoS): add unit tests to L2 Agent
@six.add_metaclass(abc.ABCMeta)
class L2Agent(object):
    """Define stable abstract interface for L2 Agent

    This class initialize the agent extension manager and
    provides API for calling the extensions manager process
    extensions methods.
    """
    def __init__(self, polling_interval):
        self.polling_interval = polling_interval
        self.agent_extensions_mgr = None
        self.resource_rpc = None

    def initialize(self):
        #TODO(QoS): get extensions from server ????
        agent_extensions = ('qos', )
        self.agent_extensions_mgr = (
            agent_extensions_manager.AgentExtensionsManager(
                agent_extensions))
        self.agent_extensions_mgr.initialize(self.resource_rpc)

    def process_network_extensions(self, context, network):
        self.agent_extensions_mgr.handle_network(
            context, network)

    def process_subnet_extensions(self, context, subnet):
        self.agent_extensions_mgr.handle_subnet(
            context, subnet)

    def process_port_extensions(self, context, port):
        self.agent_extensions_mgr.handle_port(
            context, port)
