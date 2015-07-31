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

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import base
from neutron.api.v2 import resource_helper
from neutron import manager
from neutron.plugins.common import constants


FLAVORS = 'flavors'
SERVICE_PROFILES = 'service_profiles'
FLAVORS_PREFIX = ""

RESOURCE_ATTRIBUTE_MAP = {
    FLAVORS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': True, 'default': ''},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'service_type': {'allow_post': True, 'allow_put': False,
                         'validate': {'type:string': None},
                         'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'validate': {'type:string': attr.TENANT_ID_MAX_LEN},
                      'is_visible': True},
        'service_profiles': {'allow_post': True, 'allow_put': True,
                             'validate': {'type:uuid_list': None},
                             'is_visible': True, 'default': []},
        'enabled': {'allow_post': True, 'allow_put': True,
                    'validate': {'type:boolean': None},
                    'default': True,
                    'is_visible': True},
    },
    SERVICE_PROFILES: {
        'id': {'allow_post': False, 'allow_put': False,
               'is_visible': True,
               'primary_key': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True},
        # service_profile belong to one service type for now
        #'service_types': {'allow_post': False, 'allow_put': False,
        #                  'is_visible': True},
        'driver': {'allow_post': True, 'allow_put': False,
                   'validate': {'type:string': None},
                   'is_visible': True,
                   'default': attr.ATTR_NOT_SPECIFIED},
        'metainfo': {'allow_post': True, 'allow_put': True,
                     'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'validate': {'type:string': attr.TENANT_ID_MAX_LEN},
                      'is_visible': True},
        'enabled': {'allow_post': True, 'allow_put': True,
                    'validate': {'type:boolean': None},
                    'is_visible': True, 'default': True},
    },
}


SUB_RESOURCE_ATTRIBUTE_MAP = {
    'service_profiles': {
        'parent': {'collection_name': 'flavors',
                   'member_name': 'flavor'},
        'parameters': {'id': {'allow_post': True, 'allow_put': False,
                              'validate': {'type:uuid': None},
                              'is_visible': True}}
    }
}


class Flavors(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Neutron Service Flavors"

    @classmethod
    def get_alias(cls):
        return "flavors"

    @classmethod
    def get_description(cls):
        return "Service specification for advanced services"

    @classmethod
    def get_updated(cls):
        return "2014-07-06T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        attr.PLURALS.update(plural_mappings)
        resources = resource_helper.build_resource_info(
            plural_mappings,
            RESOURCE_ATTRIBUTE_MAP,
            constants.FLAVORS)
        plugin = manager.NeutronManager.get_service_plugins()[
            constants.FLAVORS]
        for collection_name in SUB_RESOURCE_ATTRIBUTE_MAP:
            # Special handling needed for sub-resources with 'y' ending
            # (e.g. proxies -> proxy)
            resource_name = collection_name[:-1]
            parent = SUB_RESOURCE_ATTRIBUTE_MAP[collection_name].get('parent')
            params = SUB_RESOURCE_ATTRIBUTE_MAP[collection_name].get(
                'parameters')

            controller = base.create_resource(collection_name, resource_name,
                                              plugin, params,
                                              allow_bulk=True,
                                              parent=parent)

            resource = extensions.ResourceExtension(
                collection_name,
                controller, parent,
                path_prefix=FLAVORS_PREFIX,
                attr_map=params)
            resources.append(resource)

        return resources

    def update_attributes_map(self, attributes):
        super(Flavors, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}
