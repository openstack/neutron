# Copyright (C) 2013 eNovance SAS <licensing@enovance.com>
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

import abc

from neutron_lib.api.definitions import metering as metering_apidef
from neutron_lib.api import extensions
from neutron_lib.plugins import constants
from neutron_lib.services import base as service_base

from neutron.api.v2 import resource_helper


class Metering(extensions.APIExtensionDescriptor):
    api_definition = metering_apidef

    @classmethod
    def get_plugin_interface(cls):
        return MeteringPluginBase

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plural_mappings = resource_helper.build_plural_mappings(
            {}, metering_apidef.RESOURCE_ATTRIBUTE_MAP)
        # PCM: Metering sets pagination and sorting to True. Do we have cfg
        # entries for these so can be read? Else, must pass in.
        return resource_helper.build_resource_info(
            plural_mappings, metering_apidef.RESOURCE_ATTRIBUTE_MAP,
            constants.METERING, translate_name=True, allow_bulk=True)


class MeteringPluginBase(service_base.ServicePluginBase,
                         metaclass=abc.ABCMeta):

    def get_plugin_description(self):
        return constants.METERING

    @classmethod
    def get_plugin_type(cls):
        return constants.METERING

    @abc.abstractmethod
    def create_metering_label(self, context, metering_label):
        """Create a metering label."""
        pass

    def update_metering_label(self, context, id, metering_label):
        """Update a metering label."""
        raise NotImplementedError()

    @abc.abstractmethod
    def delete_metering_label(self, context, label_id):
        """Delete a metering label."""
        pass

    @abc.abstractmethod
    def get_metering_label(self, context, label_id, fields=None):
        """Get a metering label."""
        pass

    @abc.abstractmethod
    def get_metering_labels(self, context, filters=None, fields=None,
                            sorts=None, limit=None, marker=None,
                            page_reverse=False):
        """List all metering labels."""
        pass

    @abc.abstractmethod
    def create_metering_label_rule(self, context, metering_label_rule):
        """Create a metering label rule."""
        pass

    def update_metering_label_rule(self, context, id, metering_label_rule):
        """Update a metering label rule."""
        raise NotImplementedError()

    @abc.abstractmethod
    def get_metering_label_rule(self, context, rule_id, fields=None):
        """Get a metering label rule."""
        pass

    @abc.abstractmethod
    def delete_metering_label_rule(self, context, rule_id):
        """Delete a metering label rule."""
        pass

    @abc.abstractmethod
    def get_metering_label_rules(self, context, filters=None, fields=None,
                                 sorts=None, limit=None, marker=None,
                                 page_reverse=False):
        """List all metering label rules."""
        pass
