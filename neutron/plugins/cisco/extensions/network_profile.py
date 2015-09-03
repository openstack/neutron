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
    'network_profiles': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:regex': attributes.UUID_PATTERN},
               'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'is_visible': True, 'default': ''},
        'segment_type': {'allow_post': True, 'allow_put': False,
                         'is_visible': True, 'default': ''},
        'sub_type': {'allow_post': True, 'allow_put': False,
                     'is_visible': True,
                     'default': attributes.ATTR_NOT_SPECIFIED},
        'segment_range': {'allow_post': True, 'allow_put': True,
                          'is_visible': True, 'default': ''},
        'multicast_ip_range': {'allow_post': True, 'allow_put': True,
                               'is_visible': True,
                               'default': attributes.ATTR_NOT_SPECIFIED},
        'multicast_ip_index': {'allow_post': False, 'allow_put': False,
                               'is_visible': False, 'default': '0'},
        'physical_network': {'allow_post': True, 'allow_put': False,
                             'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'is_visible': False, 'default': ''},
        'add_tenants': {'allow_post': True, 'allow_put': True,
                        'is_visible': True, 'default': None,
                        'convert_to': attributes.convert_none_to_empty_list},
        'remove_tenants': {
            'allow_post': True, 'allow_put': True,
            'is_visible': True, 'default': None,
            'convert_to': attributes.convert_none_to_empty_list,
        },
    },
    'network_profile_bindings': {
        'profile_id': {'allow_post': False, 'allow_put': False,
                       'validate': {'type:regex': attributes.UUID_PATTERN},
                       'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'is_visible': True},
    },
}


class Network_profile(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Cisco N1kv Network Profiles"

    @classmethod
    def get_alias(cls):
        return 'network_profile'

    @classmethod
    def get_description(cls):
        return ("Profile includes the type of profile for N1kv")

    @classmethod
    def get_updated(cls):
        return "2012-07-20T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Extended Resources."""
        exts = []
        plugin = manager.NeutronManager.get_plugin()
        for resource_name in ['network_profile', 'network_profile_binding']:
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
