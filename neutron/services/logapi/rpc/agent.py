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

from neutron_lib import rpc as n_rpc
from neutron_lib.services.logapi import constants as log_const
from oslo_log import helpers as log_helpers
import oslo_messaging


class LoggingApiStub(object):
    """Stub proxy code for agent->server communication."""

    def __init__(self):

        target = oslo_messaging.Target(
            topic=log_const.LOGGING_PLUGIN,
            version='1.0',
            namespace=log_const.RPC_NAMESPACE_LOGGING)
        self.rpc_client = n_rpc.get_client(target)

    @log_helpers.log_method_call
    def get_sg_log_info_for_port(self, context, resource_type, port_id):
        """Return list of sg_log info for a port"""
        cctxt = self.rpc_client.prepare()
        return cctxt.call(context, 'get_sg_log_info_for_port',
                          resource_type=resource_type,
                          port_id=port_id)

    @log_helpers.log_method_call
    def get_sg_log_info_for_log_resources(self, context,
                                          resource_type, log_resources):
        """Return list of sg_log info for list of log_resources"""
        cctxt = self.rpc_client.prepare()
        return cctxt.call(context, 'get_sg_log_info_for_log_resources',
                          resource_type=resource_type,
                          log_resources=log_resources)
