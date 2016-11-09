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

from neutron.db import api as db_api
from neutron.db import db_base_plugin_common
from neutron.extensions import logging as log_ext
from neutron.objects import base as base_obj
from neutron.objects.logapi import logging_resource as log_object
from neutron.services.logapi.common import exceptions as log_exc


class LoggingPlugin(log_ext.LoggingPluginBase):
    """Implementation of the Neutron logging api plugin."""

    supported_extension_aliases = ['logging']

    __native_pagination_support = True
    __native_sorting_support = True

    @property
    def supported_logging_types(self):
        # Todo(annp): supported_logging_types will dynamic load from
        # log_drivers. So return value for this function is a temporary.
        return []

    @db_base_plugin_common.filter_fields
    @db_base_plugin_common.convert_result_to_dict
    def get_logs(self, context, filters=None, fields=None, sorts=None,
                 limit=None, marker=None, page_reverse=False):
        """Return information for available log objects"""
        filters = filters or {}
        pager = base_obj.Pager(sorts, limit, page_reverse, marker)
        return log_object.Log.get_objects(context, _pager=pager, **filters)

    def _get_log(self, context, log_id):
        """Return the log object or raise if not found"""
        log_obj = log_object.Log.get_object(context, id=log_id)
        if not log_obj:
            raise log_exc.LogResourceNotFound(log_id=log_id)
        return log_obj

    @db_base_plugin_common.filter_fields
    @db_base_plugin_common.convert_result_to_dict
    def get_log(self, context, log_id, fields=None):
        return self._get_log(context, log_id)

    @db_base_plugin_common.convert_result_to_dict
    def create_log(self, context, log):
        """Create a log object"""
        log_data = log['log']
        with db_api.context_manager.writer.using(context):
            # body 'log' contains both tenant_id and project_id
            # but only latter needs to be used to create Log object.
            # We need to remove redundant keyword.
            log_data.pop('tenant_id', None)
            log_obj = log_object.Log(context=context, **log_data)
            log_obj.create()
        return log_obj

    @db_base_plugin_common.convert_result_to_dict
    def update_log(self, context, log_id, log):
        """Update information for the specified log object"""
        log_data = log['log']
        with db_api.context_manager.writer.using(context):
            log_obj = log_object.Log(context, id=log_id)
            log_obj.update_fields(log_data, reset_changes=True)
            log_obj.update()
        return log_obj

    def delete_log(self, context, log_id):
        """Delete the specified log object"""
        with db_api.context_manager.writer.using(context):
            log_obj = self._get_log(context, log_id)
            log_obj.delete()

    def get_loggable_resources(self, context, filters=None, fields=None,
                               sorts=None, limit=None,
                               marker=None, page_reverse=False):
        """Get supported logging types"""
        return [{'type': type_}
                for type_ in self.supported_logging_types]
