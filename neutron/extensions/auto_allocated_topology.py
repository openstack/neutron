# Copyright 2015-2016 Hewlett Packard Enterprise Development Company, LP
#
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

from neutron_lib.api import converters
from neutron_lib.api import extensions as api_extensions
from neutron_lib.plugins import directory

from neutron.api import extensions
from neutron.api.v2 import base

RESOURCE_NAME = "auto_allocated_topology"
COLLECTION_NAME = "auto_allocated_topologies"
IS_DEFAULT = "is_default"
EXT_ALIAS = RESOURCE_NAME.replace('_', '-')

RESOURCE_ATTRIBUTE_MAP = {
    COLLECTION_NAME: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True},
        'tenant_id': {'allow_post': False, 'allow_put': False,
                      'validate': {'type:uuid': None},
                      'is_visible': True},
    },
    'networks': {IS_DEFAULT: {'allow_post': True,
                              'allow_put': True,
                              'default': False,
                              'is_visible': True,
                              'convert_to': converters.convert_to_boolean,
                              'enforce_policy': True,
                              'required_by_policy': True}},
}


class Auto_allocated_topology(api_extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Auto Allocated Topology Services"

    @classmethod
    def get_alias(cls):
        return EXT_ALIAS

    @classmethod
    def get_description(cls):
        return "Auto Allocated Topology Services."

    @classmethod
    def get_updated(cls):
        return "2016-01-01T00:00:00-00:00"

    @classmethod
    def get_resources(cls):
        params = RESOURCE_ATTRIBUTE_MAP.get(COLLECTION_NAME, dict())
        controller = base.create_resource(COLLECTION_NAME,
                                          EXT_ALIAS,
                                          directory.get_plugin(EXT_ALIAS),
                                          params, allow_bulk=False)
        return [extensions.ResourceExtension(EXT_ALIAS, controller)]

    def get_required_extensions(self):
        return ["subnet_allocation", "external-net", "router"]

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}
