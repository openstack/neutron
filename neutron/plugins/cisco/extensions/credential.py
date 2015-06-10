# Copyright 2013 Cisco Systems, Inc.  All rights reserved.
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

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.api.v2 import base
from neutron import manager


# Attribute Map
RESOURCE_ATTRIBUTE_MAP = {
    'credentials': {
        'credential_id': {'allow_post': False, 'allow_put': False,
                          'validate': {'type:regex': attributes.UUID_PATTERN},
                          'is_visible': True},
        'credential_name': {'allow_post': True, 'allow_put': True,
                            'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'is_visible': False, 'default': ''},
        'type': {'allow_post': True, 'allow_put': True,
                 'is_visible': True, 'default': ''},
        'user_name': {'allow_post': True, 'allow_put': True,
                      'is_visible': True, 'default': ''},
        'password': {'allow_post': True, 'allow_put': True,
                     'is_visible': True, 'default': ''},
    },
}


class Credential(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        """Returns Extended Resource Name."""
        return "Cisco Credential"

    @classmethod
    def get_alias(cls):
        """Returns Extended Resource Alias."""
        return "credential"

    @classmethod
    def get_description(cls):
        """Returns Extended Resource Description."""
        return "Credential include username and password"

    @classmethod
    def get_updated(cls):
        """Returns Extended Resource Update Time."""
        return "2011-07-25T13:25:27-06:00"

    @classmethod
    def get_resources(cls):
        """Returns Extended Resources."""
        resource_name = "credential"
        collection_name = resource_name + "s"
        plugin = manager.NeutronManager.get_plugin()
        params = RESOURCE_ATTRIBUTE_MAP.get(collection_name, dict())
        controller = base.create_resource(collection_name,
                                          resource_name,
                                          plugin, params)
        return [extensions.ResourceExtension(collection_name,
                                             controller)]
