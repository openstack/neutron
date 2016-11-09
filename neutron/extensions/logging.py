# Copyright (c) 2017 Fujitsu Limited
# All rights reserved.
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

import abc
import itertools

from neutron_lib.api import converters
from neutron_lib.api import extensions as api_extensions
from neutron_lib.db import constants as db_const
from neutron_lib.services import base as service_base
import six

from neutron.api.v2 import resource_helper
from neutron.plugins.common import constants
from neutron.services.logapi.common import constants as log_const


LOG_PREFIX = "/log"
# Attribute Map
RESOURCE_ATTRIBUTE_MAP = {
    'logs': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'project_id': {'allow_post': True, 'allow_put': False,
                       'required_by_policy': True,
                       'validate': {
                           'type:string':
                               db_const.PROJECT_ID_FIELD_SIZE},
                       'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': db_const.NAME_FIELD_SIZE},
                 'default': '', 'is_visible': True},
        'resource_type': {'allow_post': True, 'allow_put': False,
                          'required_by_policy': True,
                          'validate':
                          {'type:string': db_const.RESOURCE_TYPE_FIELD_SIZE},
                          'is_visible': True},
        'resource_id': {'allow_post': True, 'allow_put': False,
                        'validate': {'type:uuid_or_none': None},
                        'default': None, 'is_visible': True},
        'event': {'allow_post': True, 'allow_put': False,
                  'validate': {'type:values': log_const.LOG_EVENTS},
                  'default': log_const.ALL_EVENT, 'is_visible': True},
        'target_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:uuid_or_none': None},
                      'default': None, 'is_visible': True},
        'enabled': {'allow_post': True, 'allow_put': True,
                    'is_visible': True, 'default': True,
                    'convert_to': converters.convert_to_boolean},
    },

    'loggable_resources': {
        'type': {'allow_post': False, 'allow_put': False,
                 'is_visible': True}},
}


class Logging(api_extensions.ExtensionDescriptor):
    """Neutron logging api extension."""

    @classmethod
    def get_name(cls):
        return "Logging API Extension"

    @classmethod
    def get_alias(cls):
        return "logging"

    @classmethod
    def get_description(cls):
        return "Provides a logging API for resources such as security group"

    @classmethod
    def get_updated(cls):
        return "2017-01-01T10:00:00-00:00"

    @classmethod
    def get_plugin_interface(cls):
        return LoggingPluginBase

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plural_mappings = resource_helper.build_plural_mappings(
            {}, itertools.chain(RESOURCE_ATTRIBUTE_MAP))

        resources = resource_helper.build_resource_info(
                                                plural_mappings,
                                                RESOURCE_ATTRIBUTE_MAP,
                                                constants.LOG_API,
                                                translate_name=True,
                                                allow_bulk=True)

        return resources

    def update_attributes_map(self, attributes, extension_attrs_map=None):
        super(Logging, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return dict(list(RESOURCE_ATTRIBUTE_MAP.items()))
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class LoggingPluginBase(service_base.ServicePluginBase):

    path_prefix = LOG_PREFIX

    def get_plugin_description(self):
        return "Logging API Service Plugin"

    @classmethod
    def get_plugin_type(cls):
        return constants.LOG_API

    @abc.abstractmethod
    def get_logs(self, context, filters=None, fields=None, sorts=None,
                 limit=None, marker=None, page_reverse=False):
        pass

    @abc.abstractmethod
    def get_log(self, context, log_id, fields=None):
        pass

    @abc.abstractmethod
    def create_log(self, context, log):
        pass

    @abc.abstractmethod
    def update_log(self, context, log_id, log):
        pass

    @abc.abstractmethod
    def delete_log(self, context, log_id):
        pass

    @abc.abstractmethod
    def get_loggable_resources(self, context, filters=None, fields=None,
                               sorts=None, limit=None,
                               marker=None, page_reverse=False):
        pass
