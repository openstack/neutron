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

from neutron_lib.plugins.ml2 import api
from oslo_log import log as logging

from neutron.core_extensions import base as base_core
from neutron.core_extensions import qos as qos_core

LOG = logging.getLogger(__name__)

QOS_EXT_DRIVER_ALIAS = 'qos'


class QosExtensionDriver(api.ExtensionDriver):

    def initialize(self):
        self.core_ext_handler = qos_core.QosCoreResourceExtension()
        LOG.debug("QosExtensionDriver initialization complete")

    def process_create_network(self, context, data, result):
        self.core_ext_handler.process_fields(
            context, base_core.NETWORK, base_core.EVENT_CREATE, data, result)

    def process_update_network(self, context, data, result):
        self.core_ext_handler.process_fields(
            context, base_core.NETWORK, base_core.EVENT_UPDATE, data, result)

    def process_create_port(self, context, data, result):
        self.core_ext_handler.process_fields(
            context, base_core.PORT, base_core.EVENT_UPDATE, data, result)

    process_update_port = process_create_port

    def extend_network_dict(self, session, db_data, result):
        result.update(
            self.core_ext_handler.extract_fields(
                base_core.NETWORK, db_data))

    def extend_port_dict(self, session, db_data, result):
        result.update(
            self.core_ext_handler.extract_fields(base_core.PORT, db_data))
