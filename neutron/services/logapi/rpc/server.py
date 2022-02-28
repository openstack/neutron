# Copyright (C) 2017 Fujitsu Limited
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

from neutron_lib.callbacks import resources as r_const
from neutron_lib import rpc as n_rpc
from neutron_lib.services.logapi import constants as log_const
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
import oslo_messaging

from neutron.api.rpc.callbacks import events
from neutron.api.rpc.handlers import resources_rpc
from neutron.services.logapi import api_base
from neutron.services.logapi.common import db_api

LOG = logging.getLogger(__name__)

# RPC methods mapping
RPC_RESOURCES_METHOD_MAP = {}


# This function must be called when a log_driver is registered.
def register_rpc_methods(resource_type, rpc_methods):
    """Register RPC methods.

    :param resource_type: string and must be a valid resource type.
    :param rpc_methods: list of RPC methods to be registered.
           This param would look like:
           [
               {'PORT': get_sg_log_info_for_port},
               {'LOG_RESOURCE': get_sg_log_info_for_log_resources}
           ]
    """
    if resource_type not in RPC_RESOURCES_METHOD_MAP:
        RPC_RESOURCES_METHOD_MAP[resource_type] = rpc_methods


def get_rpc_method(resource_type, rpc_method_key):
    if resource_type not in RPC_RESOURCES_METHOD_MAP:
        raise NotImplementedError()

    for rpc_method in RPC_RESOURCES_METHOD_MAP[resource_type]:
        if rpc_method_key in rpc_method.keys():
            return list(rpc_method.values())[0]

    raise NotImplementedError()


def get_sg_log_info_for_port(context, port_id):
    return db_api.get_sg_log_info_for_port(context, port_id)


def get_sg_log_info_for_log_resources(context, log_resources):
    return db_api.get_sg_log_info_for_log_resources(context, log_resources)


class LoggingApiSkeleton(object):
    """Skeleton proxy code for agent->server communication."""

    # History
    #   1.0 Initial version
    #   1.1 Introduce resource_type as a keyword in order to extend
    #   support for other resources

    target = oslo_messaging.Target(
        version='1.1', namespace=log_const.RPC_NAMESPACE_LOGGING)

    def __init__(self):
        self.conn = n_rpc.Connection()
        self.conn.create_consumer(log_const.LOGGING_PLUGIN, [self],
                                  fanout=False)

    @log_helpers.log_method_call
    def get_sg_log_info_for_port(self, context, port_id, **kwargs):
        resource_type = kwargs.get('resource_type', log_const.SECURITY_GROUP)
        LOG.debug("Logging agent requests log info "
                  "for port with resource type %s", resource_type)
        rpc_method = get_rpc_method(resource_type, r_const.PORT)
        return rpc_method(context, port_id)

    @log_helpers.log_method_call
    def get_sg_log_info_for_log_resources(self, context,
                                          log_resources, **kwargs):
        resource_type = kwargs.get('resource_type', log_const.SECURITY_GROUP)
        LOG.debug("Logging agent requests log info "
                  "for log resources with resource type %s", resource_type)
        rpc_method = get_rpc_method(resource_type, log_const.LOG_RESOURCE)
        return rpc_method(context, log_resources)


class LoggingApiNotification(api_base.LoggingApiBase):

    def __init__(self):
        self.notification_api = resources_rpc.ResourcesPushRpcApi()

    @log_helpers.log_method_call
    def create_log(self, context, log_obj):
        self.notification_api.push(context, [log_obj], events.CREATED)

    def create_log_precommit(self, context, log_obj):
        pass

    @log_helpers.log_method_call
    def update_log(self, context, log_obj):
        self.notification_api.push(context, [log_obj], events.UPDATED)

    def update_log_precommit(self, context, log_obj):
        pass

    @log_helpers.log_method_call
    def delete_log(self, context, log_obj):
        self.notification_api.push(context, [log_obj], events.DELETED)

    def delete_log_precommit(self, context, log_obj):
        pass

    @log_helpers.log_method_call
    def resource_update(self, context, log_objs):
        """Tell to agent when resources related to log_objects updated"""
        self.notification_api.push(context, log_objs, events.UPDATED)
