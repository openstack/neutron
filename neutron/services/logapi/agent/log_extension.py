# Copyright (c) 2017 Fujitsu Limited
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
import contextlib

from neutron_lib.agent import extension
from neutron_lib import constants
from oslo_concurrency import lockutils

from neutron.api.rpc.callbacks.consumer import registry
from neutron.api.rpc.callbacks import events
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import resources_rpc
from neutron.conf.services import logging as log_cfg
from neutron import manager
from neutron.services.logapi.rpc import agent as agent_rpc

log_cfg.register_log_driver_opts()

LOGGING_DRIVERS_NAMESPACE = 'neutron.services.logapi.drivers'


class LoggingDriver(metaclass=abc.ABCMeta):
    """Defines abstract interface for logging driver"""

    # specific logging types are supported
    SUPPORTED_LOGGING_TYPES = tuple()

    @abc.abstractmethod
    def initialize(self, resource_rpc, **kwargs):
        """Perform logging driver initialization.
        """

    @abc.abstractmethod
    def start_logging(self, context, **kwargs):
        """Enable logging

        :param context: rpc context
        :param kwargs: log_resources data or port_id
        """

    @abc.abstractmethod
    def stop_logging(self, context, **kwargs):
        """Disable logging

        :param context: rpc context
        :param kwargs: log_resources data or port_id
        """

    def defer_apply_on(self):
        """Defer application of logging rule."""
        pass

    def defer_apply_off(self):
        """Turn off deferral of rules and apply the logging rules now."""
        pass

    @contextlib.contextmanager
    def defer_apply(self):
        """Defer apply context."""
        self.defer_apply_on()
        try:
            yield
        finally:
            self.defer_apply_off()


class LoggingExtension(extension.AgentExtension):
    SUPPORTED_RESOURCE_TYPES = [resources.LOGGING_RESOURCE]

    def initialize(self, connection, driver_type):
        """Initialize agent extension."""

        self.log_driver = manager.NeutronManager.load_class_for_provider(
            LOGGING_DRIVERS_NAMESPACE, driver_type)(self.agent_api)
        self.resource_rpc = agent_rpc.LoggingApiStub()
        self._register_rpc_consumers(connection)
        self.log_driver.initialize(self.resource_rpc)

    def consume_api(self, agent_api):
        self.agent_api = agent_api

    def _register_rpc_consumers(self, connection):
        endpoints = [resources_rpc.ResourcesPushRpcCallback()]
        for resource_type in self.SUPPORTED_RESOURCE_TYPES:
            registry.register(self._handle_notification, resource_type)
            topic = resources_rpc.resource_type_versioned_topic(resource_type)
            connection.create_consumer(topic, endpoints, fanout=True)

    @lockutils.synchronized('log-port')
    def _handle_notification(self, context, resource_type,
                             log_resources, event_type):
        with self.log_driver.defer_apply():
            if event_type == events.UPDATED:
                self._update_logging(context, log_resources)
            elif event_type == events.CREATED:
                self.log_driver.start_logging(
                    context, log_resources=log_resources)
            elif event_type == events.DELETED:
                self.log_driver.stop_logging(
                    context, log_resources=log_resources)

    @lockutils.synchronized('log-port')
    def handle_port(self, context, port):
        if port['device_owner'].startswith(
                constants.DEVICE_OWNER_COMPUTE_PREFIX):
            self.log_driver.start_logging(context, port_id=port['port_id'])

    def delete_port(self, context, port):
        self.log_driver.stop_logging(context, port_id=port['port_id'])

    def _update_logging(self, context, log_resources):
        enables = []
        disables = []
        for log_resource in log_resources:
            if log_resource.enabled:
                enables.append(log_resource)
            else:
                disables.append(log_resource)
        if enables:
            self.log_driver.start_logging(context, log_resources=enables)
        if disables:
            self.log_driver.stop_logging(context, log_resources=disables)
