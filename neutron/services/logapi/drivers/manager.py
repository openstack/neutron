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

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib import exceptions
from neutron_lib.services.logapi import constants as log_const
from oslo_log import log as logging

from neutron.services.logapi.common import exceptions as log_exc
from neutron.services.logapi.rpc import server as server_rpc

LOG = logging.getLogger(__name__)

RESOURCE_CB_CLASS_MAP = {}


# This function should be called by log_driver
def register(resource_type, obj_class):
    if resource_type not in RESOURCE_CB_CLASS_MAP:
        RESOURCE_CB_CLASS_MAP[resource_type] = obj_class


def _get_param(args, kwargs, name, index):
    try:
        return kwargs[name]
    except KeyError:
        try:
            return args[index]
        except IndexError:
            msg = "Missing parameter %s" % name
            raise log_exc.LogapiDriverException(exception_msg=msg)


class ResourceCallBackBase:

    def __new__(cls, *args, **kwargs):
        if not hasattr(cls, '_instance'):
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, resource, push_api):
        self.resource_push_api = push_api
        for event in (events.AFTER_CREATE, events.AFTER_UPDATE,
                      events.AFTER_DELETE):
            registry.subscribe(self.handle_event, resource, event)

    def handle_event(self, resource, event, trigger, payload):
        """Handle resource callback event"""
        pass


class LoggingServiceDriverManager:

    def __init__(self):
        self._drivers = set()
        self.rpc_required = False
        registry.publish(log_const.LOGGING_PLUGIN, events.AFTER_INIT, self)

        if self.rpc_required:
            self.logging_rpc = server_rpc.LoggingApiNotification()

    @property
    def drivers(self):
        return self._drivers

    def register_driver(self, driver):
        """Register driver with logging plugin.

        This method is called from drivers on INIT event.
        """
        self._drivers.add(driver)
        self.rpc_required |= driver.requires_rpc

        # Handle callback event AFTER_UPDATE, AFTER_DELETE, AFTER_CREATE of
        # resources which related to log object. For example: when a sg_rule
        # is added or deleted from security group, if this rule is bounded by a
        # log_resources, then it should tell to agent to trigger log_drivers.
        self._setup_resources_cb_handle()

    def _start_rpc_listeners(self):
        if not self.rpc_required:
            return []

        self._skeleton = server_rpc.LoggingApiSkeleton()
        return self._skeleton.conn.consume_in_threads()

    @property
    def supported_logging_types(self):
        if not self._drivers:
            return set()

        log_types = set()

        for driver in self._drivers:
            log_types |= set(driver.supported_logging_types)
        LOG.debug("Supported logging types (logging types supported "
                  "by at least one loaded log_driver): %s", log_types)
        return log_types

    def call(self, method_name, *args, **kwargs):
        """Helper method for calling a method across all extension drivers."""
        exc_list = []
        for driver in self._drivers:
            try:
                getattr(driver, method_name)(*args, **kwargs)
            except Exception as exc:
                exception_msg = ("Extension driver '%(name)s' failed in "
                                 "%(method)s")
                exception_data = {'name': driver.name, 'method': method_name}
                LOG.exception(exception_msg, exception_data)
                exc_list.append(exc)

        if exc_list:
            raise exceptions.DriverCallError(exc_list=exc_list)

        if self.rpc_required:
            context = _get_param(args, kwargs, 'context', index=0)
            log_obj = _get_param(args, kwargs, 'log_obj', index=1)

            try:
                rpc_method = getattr(self.logging_rpc, method_name)
            except AttributeError:
                LOG.error("Method %s is not implemented in logging RPC",
                          method_name)
                return
            rpc_method(context, log_obj)

    def _setup_resources_cb_handle(self):
        for res, obj_class in RESOURCE_CB_CLASS_MAP.items():
            obj_class(res, self.call)
