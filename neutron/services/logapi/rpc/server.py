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

from oslo_log import helpers as log_helpers
import oslo_messaging

from neutron.api.rpc.callbacks import events
from neutron.api.rpc.handlers import resources_rpc
from neutron.common import rpc as n_rpc
from neutron.services.logapi.common import constants as log_const
from neutron.services.logapi.common import db_api


class LoggingApiSkeleton(object):
    """Skeleton proxy code for agent->server communication."""

    # History
    #   1.0 Initial version

    target = oslo_messaging.Target(
        version='1.0', namespace=log_const.RPC_NAMESPACE_LOGGING)

    def __init__(self):
        self.conn = n_rpc.create_connection()
        self.conn.create_consumer(log_const.LOGGING_PLUGIN, [self],
                                  fanout=False)

    @log_helpers.log_method_call
    def get_sg_log_info_for_port(self, context, port_id):
        return db_api.get_sg_log_info_for_port(context, port_id)

    @log_helpers.log_method_call
    def get_sg_log_info_for_log_resources(self, context, log_resources):
        return db_api.get_sg_log_info_for_log_resources(context, log_resources)


class LoggingApiNotification(object):

    def __init__(self):
        self.notification_api = resources_rpc.ResourcesPushRpcApi()

    @log_helpers.log_method_call
    def create_log(self, context, log_obj):
        self.notification_api.push(context, [log_obj], events.CREATED)

    @log_helpers.log_method_call
    def update_log(self, context, log_obj):
        self.notification_api.push(context, [log_obj], events.UPDATED)

    @log_helpers.log_method_call
    def delete_log(self, context, log_obj):
        self.notification_api.push(context, [log_obj], events.DELETED)

    @log_helpers.log_method_call
    def resource_update(self, context, log_objs):
        """Tell to agent when resources related to log_objects updated"""
        self.notification_api.push(context, log_objs, events.UPDATED)
