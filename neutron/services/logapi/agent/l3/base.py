# Copyright (c) 2018 Fujitsu Limited
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

from neutron_lib import rpc as n_rpc
from oslo_concurrency import lockutils
from oslo_log import log as logging

from neutron.api.rpc.callbacks.consumer import registry
from neutron.api.rpc.callbacks import events
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import resources_rpc
from neutron.conf.services import logging as log_cfg
from neutron import manager

LOG = logging.getLogger(__name__)

log_cfg.register_log_driver_opts()


class L3LoggingExtensionBase(object):
    """Base class for l3 logging extension like

    SNATLogExtension, FWaaSV2LogExtension
    """

    SUPPORTED_RESOURCE_TYPES = [resources.LOGGING_RESOURCE]

    def consume_api(self, agent_api):
        self.agent_api = agent_api

    def _load_driver_cls(self, namesapce, driver_name):
        return manager.NeutronManager.load_class_for_provider(
            namesapce, driver_name)

    def _register_rpc_consumers(self):
        registry.register(
            self._handle_notification, resources.LOGGING_RESOURCE)
        self._connection = n_rpc.Connection()
        endpoints = [resources_rpc.ResourcesPushRpcCallback()]
        topic = resources_rpc.resource_type_versioned_topic(
            resources.LOGGING_RESOURCE)
        self._connection.create_consumer(topic, endpoints, fanout=True)
        self._connection.consume_in_threads()

    def _get_router_info(self, router_id):
        router_info = self.agent_api.get_router_info(router_id)
        if router_info:
            return router_info
        LOG.debug("Router %s is not managed by this agent. "
                  "It was possibly deleted concurrently.",
                  router_id)

    @lockutils.synchronized('log')
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

    def _process_update_router(self, context, router):
        router_info = self._get_router_info(router['id'])
        if router_info:
            self.log_driver.start_logging(context, router_info=router_info)

    @lockutils.synchronized('log-port')
    def add_router(self, context, data):
        self._process_update_router(context, data)

    @lockutils.synchronized('log-port')
    def update_router(self, context, data):
        self._process_update_router(context, data)

    def delete_router(self, context, data):
        self.log_driver.stop_logging(context, router_info=data)

    def ha_state_change(self, context, data):
        pass
