# Copyright 2023 Ericsson Software Technology
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from neutron_lib.api.definitions import port_hints as phints_def
from neutron_lib.plugins.ml2 import api
from oslo_log import log as logging

from neutron.db import port_hints_db


LOG = logging.getLogger(__name__)


class PortHintsExtensionDriver(
        api.ExtensionDriver, port_hints_db.PortHintsMixin):

    _supported_extension_alias = phints_def.ALIAS

    def initialize(self):
        LOG.info('PortHintsExtensionDriver initialization complete')

    @property
    def extension_alias(self):
        return self._supported_extension_alias

    def process_create_port(self, context, data, result):
        self._process_create_port(context, data, result)

    def process_update_port(self, context, data, result):
        if phints_def.HINTS in data:
            self._process_update_port(context, data, result)

    def extend_port_dict(self, session, port_db, result):
        self._extend_port_dict(port_db, result)
