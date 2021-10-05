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

from neutron_lib.api.definitions import logging
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib.db import api as db_api
from neutron_lib.services.logapi import constants as log_const

from neutron.db import db_base_plugin_common
from neutron.extensions import logging as log_ext
from neutron.objects import base as base_obj
from neutron.objects.logapi import logging_resource as log_object
from neutron.services.logapi.common import db_api as log_db_api
from neutron.services.logapi.common import exceptions as log_exc
from neutron.services.logapi.common import validators
from neutron.services.logapi.drivers import manager as driver_mgr


@registry.has_registry_receivers
class LoggingPlugin(log_ext.LoggingPluginBase):
    """Implementation of the Neutron logging api plugin."""

    supported_extension_aliases = [logging.ALIAS]

    __native_pagination_support = True
    __native_sorting_support = True
    __filter_validation_support = True

    def __init__(self):
        super(LoggingPlugin, self).__init__()
        self.driver_manager = driver_mgr.LoggingServiceDriverManager()
        self.validator_mgr = validators.ResourceValidateRequest.get_instance()

    @property
    def supported_logging_types(self):
        # supported_logging_types are be dynamically loaded from log_drivers
        return self.driver_manager.supported_logging_types

    def _clean_logs(self, context, sg_id=None, port_id=None):
        with db_api.CONTEXT_WRITER.using(context):
            sg_logs = log_db_api.get_logs_bound_sg(
                context, sg_id=sg_id, port_id=port_id, exclusive=True)
            for log in sg_logs:
                self.delete_log(context, log['id'])

    @registry.receives(resources.SECURITY_GROUP, [events.AFTER_DELETE])
    def _clean_logs_by_resource_id(self, resource, event, trigger, payload):
        # log.resource_id == SG
        self._clean_logs(payload.context.elevated(), sg_id=payload.resource_id)

    @registry.receives(resources.PORT, [events.AFTER_DELETE])
    def _clean_logs_by_target_id(self, resource, event, trigger, payload):
        # log.target_id == port
        self._clean_logs(payload.context.elevated(),
                         port_id=payload.resource_id)

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
        self.validator_mgr.validate_request(context, log_data)
        with db_api.CONTEXT_WRITER.using(context):
            # body 'log' contains both tenant_id and project_id
            # but only latter needs to be used to create Log object.
            # We need to remove redundant keyword.
            log_data.pop('tenant_id', None)
            log_obj = log_object.Log(context=context, **log_data)
            log_obj.create()
            if log_obj.enabled:
                self.driver_manager.call(
                    log_const.CREATE_LOG_PRECOMMIT, context, log_obj)
        if log_obj.enabled:
            self.driver_manager.call(
                log_const.CREATE_LOG, context, log_obj)
        return log_obj

    @db_base_plugin_common.convert_result_to_dict
    def update_log(self, context, log_id, log):
        """Update information for the specified log object"""
        log_data = log['log']
        with db_api.CONTEXT_WRITER.using(context):
            log_obj = log_object.Log(context, id=log_id)
            log_obj.update_fields(log_data, reset_changes=True)
            log_obj.update()
            need_notify = 'enabled' in log_data
            if need_notify:
                self.driver_manager.call(
                    log_const.UPDATE_LOG_PRECOMMIT, context, log_obj)
        if need_notify:
            self.driver_manager.call(
                log_const.UPDATE_LOG, context, log_obj)
        return log_obj

    def delete_log(self, context, log_id):
        """Delete the specified log object"""
        with db_api.CONTEXT_WRITER.using(context):
            log_obj = self._get_log(context, log_id)
            log_obj.delete()
            self.driver_manager.call(
                log_const.DELETE_LOG_PRECOMMIT, context, log_obj)
        self.driver_manager.call(
            log_const.DELETE_LOG, context, log_obj)

    def get_loggable_resources(self, context, filters=None, fields=None,
                               sorts=None, limit=None,
                               marker=None, page_reverse=False):
        """Get supported logging types"""
        return [{'type': type_}
                for type_ in self.supported_logging_types]
