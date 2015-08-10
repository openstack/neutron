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
from neutron.api.rpc.callbacks.consumer import registry
from neutron.api.rpc.callbacks import events
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
    SUPPORTED_RESOURCES = [resources.QOS_POLICY]

    def initialize(self, connection):
        """Perform Agent Extension initialization.

        """
        super(QosAgentExtension, self).initialize()

        self.resource_rpc = resources_rpc.ResourcesPullRpcApi()
        self.qos_driver = manager.NeutronManager.load_class_for_provider(
            'neutron.qos.agent_drivers', cfg.CONF.qos.agent_driver)()
        self.qos_driver.initialize()

        # we cannot use a dict of sets here because port dicts are not hashable
        self.qos_policy_ports = collections.defaultdict(dict)
        self.known_ports = set()

        registry.subscribe(self._handle_notification, resources.QOS_POLICY)
        self._register_rpc_consumers(connection)

    def _register_rpc_consumers(self, connection):
        endpoints = [resources_rpc.ResourcesPushRpcCallback()]
        for resource_type in self.SUPPORTED_RESOURCES:
            # we assume that neutron-server always broadcasts the latest
            # version known to the agent
            topic = resources_rpc.resource_type_versioned_topic(resource_type)
            connection.create_consumer(topic, endpoints, fanout=True)

    def _handle_notification(self, qos_policy, event_type):
        # server does not allow to remove a policy that is attached to any
        # port, so we ignore DELETED events. Also, if we receive a CREATED
        # event for a policy, it means that there are no ports so far that are
        # attached to it. That's why we are interested in UPDATED events only
        if event_type == events.UPDATED:
            self._process_update_policy(qos_policy)

    def handle_port(self, context, port):
        """Handle agent QoS extension for port.

        This method applies a new policy to a port using the QoS driver.
        Update events are handled in _handle_notification.
        """
        port_id = port['port_id']
        qos_policy_id = port.get('qos_policy_id')
        if qos_policy_id is None:
            self._process_reset_port(port)
            return

        #Note(moshele) check if we have seen this port
        #and it has the same policy we do nothing.
        if (port_id in self.known_ports and
                port_id in self.qos_policy_ports[qos_policy_id]):
            return

        # TODO(QoS): handle race condition between push and pull APIs
        self.qos_policy_ports[qos_policy_id][port_id] = port
        self.known_ports.add(port_id)
        qos_policy = self.resource_rpc.pull(
            context, resources.QOS_POLICY, qos_policy_id)
        self.qos_driver.create(port, qos_policy)

    def delete_port(self, context, port):
        self._process_reset_port(port)

    def _process_update_policy(self, qos_policy):
        for port_id, port in self.qos_policy_ports[qos_policy.id].items():
            # TODO(QoS): for now, just reflush the rules on the port. Later, we
            # may want to apply the difference between the rules lists only.
            self.qos_driver.delete(port, None)
            self.qos_driver.update(port, qos_policy)

    def _process_reset_port(self, port):
        port_id = port['port_id']
        if port_id in self.known_ports:
            self.known_ports.remove(port_id)
            for qos_policy_id, port_dict in self.qos_policy_ports.items():
                if port_id in port_dict:
                    del port_dict[port_id]
                    self.qos_driver.delete(port, None)
                    return
