# Copyright (c) 2017 NEC Corporation.  All rights reserved.
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

from neutron_lib.api.definitions import data_plane_status as dps_lib
from neutron_lib.plugins.ml2 import api
from oslo_log import log as logging

from neutron.db import data_plane_status_db as dps_db

LOG = logging.getLogger(__name__)


class DataPlaneStatusExtensionDriver(api.ExtensionDriver,
                                     dps_db.DataPlaneStatusMixin):
    _supported_extension_alias = 'data-plane-status'

    def initialize(self):
        LOG.info("DataPlaneStatusExtensionDriver initialization complete")

    @property
    def extension_alias(self):
        return self._supported_extension_alias

    def process_update_port(self, plugin_context, data, result):
        if dps_lib.DATA_PLANE_STATUS in data:
            self._process_update_port_data_plane_status(plugin_context,
                                                        data, result)

    def extend_port_dict(self, session, db_data, result):
        self._extend_port_data_plane_status(result, db_data)
