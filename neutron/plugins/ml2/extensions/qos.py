# Copyright (c) 2015 Red Hat Inc.
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

from oslo_log import log as logging

from neutron.plugins.ml2 import driver_api as api
from neutron.services.qos import qos_extension

LOG = logging.getLogger(__name__)


class QosExtensionDriver(api.ExtensionDriver):

    def initialize(self):
        self.qos_ext_handler = qos_extension.QosResourceExtensionHandler()
        LOG.debug("QosExtensionDriver initialization complete")

    def process_create_network(self, context, data, result):
        self.qos_ext_handler.process_resource(
            context, qos_extension.NETWORK, data, result)

    process_update_network = process_create_network

    def process_create_port(self, context, data, result):
        self.qos_ext_handler.process_resource(
            context, qos_extension.PORT, data, result)

    process_update_port = process_create_port

    def extend_network_dict(self, session, db_data, result):
        result.update(
            self.qos_ext_handler.extract_resource_fields(qos_extension.NETWORK,
                                                         db_data))

    def extend_port_dict(self, session, db_data, result):
        result.update(
            self.qos_ext_handler.extract_resource_fields(qos_extension.PORT,
                                                         db_data))
