# Copyright 2013 VMware, Inc.
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

from neutron_lib.api import extensions as api_extensions
from neutron_lib.plugins import directory

from neutron.api import extensions
from neutron.api.v2 import base
from neutron.quota import resource_registry


# Attribute Map
RESOURCE_ATTRIBUTE_MAP = {
    'ext_test_resources': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'validate': {'type:string': None},
                      'is_visible': True},
    }
}


class Extensionattribute(api_extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Extension Test Resource"

    @classmethod
    def get_alias(cls):
        return "ext-obj-test"

    @classmethod
    def get_description(cls):
        return "Extension Test Resource"

    @classmethod
    def get_updated(cls):
        return "2013-02-05T10:00:00-00:00"

    def update_attributes_map(self, attributes):
        super().update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        exts = []
        plugin = directory.get_plugin()
        resource_name = 'ext_test_resource'
        collection_name = resource_name + "s"
        params = RESOURCE_ATTRIBUTE_MAP.get(collection_name, dict())

        resource_registry.register_resource_by_name(resource_name)

        controller = base.create_resource(collection_name,
                                          resource_name,
                                          plugin, params,
                                          member_actions={})

        ex = extensions.ResourceExtension(collection_name,
                                          controller,
                                          member_actions={})
        exts.append(ex)

        return exts

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        return {}


class ExtensionObjectTestPluginBase:

    @abc.abstractmethod
    def create_ext_test_resource(self, context, router):
        pass

    @abc.abstractmethod
    def get_ext_test_resource(self, context, id, fields=None):
        pass
