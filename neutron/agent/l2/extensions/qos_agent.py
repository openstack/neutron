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
import collections

from oslo_config import cfg
import six

from neutron.agent.l2 import agent_extension
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import resources_rpc
from neutron import manager


@six.add_metaclass(abc.ABCMeta)
class QosAgentDriver(object):
    """Define stable abstract interface for QoS Agent Driver.

    QoS Agent driver defines the interface to be implemented by Agent
    for applying QoS Rules on a port.
    """

    @abc.abstractmethod
    def initialize(self):
        """Perform QoS agent driver initialization.
        """
        pass

    @abc.abstractmethod
    def create(self, port, qos_policy):
        """Apply QoS rules on port for the first time.

        :param port: port object.
        :param qos_policy: the QoS policy to be applied on port.
        """
        #TODO(QoS) we may want to provide default implementations of calling
        #delete and then update
        pass

    @abc.abstractmethod
    def update(self, port, qos_policy):
        """Apply QoS rules on port.

        :param port: port object.
        :param qos_policy: the QoS policy to be applied on port.
        """
        pass

    @abc.abstractmethod
    def delete(self, port, qos_policy):
        """Remove QoS rules from port.

        :param port: port object.
        :param qos_policy: the QoS policy to be removed from port.
        """
        pass


class QosAgentExtension(agent_extension.AgentCoreResourceExtension):
    def initialize(self):
        """Perform Agent Extension initialization.

        """
        super(QosAgentExtension, self).initialize()

        self.resource_rpc = resources_rpc.ResourcesServerRpcApi()
        self.qos_driver = manager.NeutronManager.load_class_for_provider(
            'neutron.qos.agent_drivers', cfg.CONF.qos.agent_driver)()
        self.qos_driver.initialize()
        self.qos_policy_ports = collections.defaultdict(dict)
        self.known_ports = set()

    def handle_port(self, context, port):
        """Handle agent QoS extension for port.

        This method subscribes to qos_policy_id changes
        with a callback and get all the qos_policy_ports and apply
        them using the QoS driver.
        Updates and delete event should be handle by the registered
        callback.
        """
        port_id = port['port_id']
        qos_policy_id = port.get('qos_policy_id')
        if qos_policy_id is None:
            #TODO(QoS):  we should also handle removing policy
            return

        #Note(moshele) check if we have seen this port
        #and it has the same policy we do nothing.
        if (port_id in self.known_ports and
                port_id in self.qos_policy_ports[qos_policy_id]):
            return

        self.qos_policy_ports[qos_policy_id][port_id] = port
        self.known_ports.add(port_id)
        #TODO(QoS): handle updates when implemented
        # we have two options:
        # 1. to add new api for subscribe
        #    registry.subscribe(self._process_policy_updates,
        #                   resources.QOS_POLICY, qos_policy_id)
        # 2. combine get_info rpc to also subscribe to the resource
        qos_policy = self.resource_rpc.get_info(
            context,
            resources.QOS_POLICY,
            qos_policy_id)
        self._process_policy_updates(
            port, resources.QOS_POLICY, qos_policy_id,
            qos_policy, 'create')

    def _process_policy_updates(
            self, port, resource_type, resource_id,
            qos_policy, action_type):
        getattr(self.qos_driver, action_type)(port, qos_policy)
