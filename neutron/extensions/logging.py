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

from neutron_lib.api.definitions import logging as apidef
from neutron_lib.api import extensions as api_extensions
from neutron_lib.plugins import constants as plugin_const
from neutron_lib.services import base as service_base
import six

from neutron.api.v2 import resource_helper


class Logging(api_extensions.APIExtensionDescriptor):
    """Neutron logging api extension."""

    api_definition = apidef

    @classmethod
    def get_plugin_interface(cls):
        return LoggingPluginBase

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plural_mappings = resource_helper.build_plural_mappings(
            {}, itertools.chain(apidef.RESOURCE_ATTRIBUTE_MAP))

        resources = resource_helper.build_resource_info(
                                                plural_mappings,
                                                apidef.RESOURCE_ATTRIBUTE_MAP,
                                                plugin_const.LOG_API,
                                                translate_name=True,
                                                allow_bulk=True)

        return resources


@six.add_metaclass(abc.ABCMeta)
class LoggingPluginBase(service_base.ServicePluginBase):

    path_prefix = apidef.API_PREFIX

    def get_plugin_description(self):
        return "Logging API Service Plugin"

    @classmethod
    def get_plugin_type(cls):
        return plugin_const.LOG_API

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
