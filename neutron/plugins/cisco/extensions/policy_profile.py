# Copyright 2013 Cisco Systems, Inc.
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
    'policy_profiles': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:regex': attributes.UUID_PATTERN},
               'is_visible': True},
        'name': {'allow_post': False, 'allow_put': False,
                 'is_visible': True, 'default': ''},
        'add_tenant': {'allow_post': True, 'allow_put': True,
                       'is_visible': True, 'default': None},
        'remove_tenant': {'allow_post': True, 'allow_put': True,
                          'is_visible': True, 'default': None},
    },
    'policy_profile_bindings': {
        'profile_id': {'allow_post': False, 'allow_put': False,
                       'validate': {'type:regex': attributes.UUID_PATTERN},
                       'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'is_visible': True},
    },
}


class Policy_profile(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Cisco Nexus1000V Policy Profiles"

    @classmethod
    def get_alias(cls):
        return 'policy_profile'

    @classmethod
    def get_description(cls):
        return "Profile includes the type of profile for N1kv"

    @classmethod
    def get_updated(cls):
        return "2012-07-20T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Extended Resources."""
        exts = []
        plugin = manager.NeutronManager.get_plugin()
        for resource_name in ['policy_profile', 'policy_profile_binding']:
            collection_name = resource_name + "s"
            controller = base.create_resource(
                collection_name,
                resource_name,
                plugin,
                RESOURCE_ATTRIBUTE_MAP.get(collection_name))
            ex = extensions.ResourceExtension(collection_name,
                                              controller)
            exts.append(ex)
        return exts
