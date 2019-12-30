# Copyright (c) 2019 Verizon Media
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

from neutron_lib.api.definitions import \
    tag_ports_during_bulk_creation as apidef
from neutron_lib.plugins import directory
from neutron_lib.plugins.ml2 import api
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from neutron.extensions import tagging

LOG = logging.getLogger(__name__)


class TagPortsDuringBulkCreationExtensionDriver(api.ExtensionDriver):
    _supported_extension_alias = apidef.ALIAS

    def initialize(self):
        LOG.info("TagPortsDuringBulkCreationExtensionDriver "
                 "initialization complete")

    @property
    def extension_alias(self):
        return self._supported_extension_alias

    @property
    def tag_plugin(self):
        if not hasattr(self, '_tag_plugin'):
            self._tag_plugin = directory.get_plugin(tagging.TAG_PLUGIN_TYPE)
        return self._tag_plugin

    @property
    def plugin(self):
        if not hasattr(self, '_plugin'):
            self._plugin = directory.get_plugin()
        return self._plugin

    @log_helpers.log_method_call
    def process_create_port(self, plugin_context, request_data, db_data):
        tags = request_data.get('tags')
        if not (self.tag_plugin and tags):
            return
        port_db = self.plugin._get_port(plugin_context, db_data['id'])
        self.tag_plugin.add_tags(plugin_context, port_db.standard_attr_id,
                                 tags)
