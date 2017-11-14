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

from neutron_lib.api.definitions import flavors as apidef
from neutron_lib.api import extensions as api_extensions
from neutron_lib.plugins import constants
from neutron_lib.plugins import directory

from neutron.api import extensions
from neutron.api.v2 import base
from neutron.api.v2 import resource_helper


class Flavors(api_extensions.APIExtensionDescriptor):

    api_definition = apidef

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plural_mappings = resource_helper.build_plural_mappings(
            {}, apidef.RESOURCE_ATTRIBUTE_MAP)
        resources = resource_helper.build_resource_info(
            plural_mappings,
            apidef.RESOURCE_ATTRIBUTE_MAP,
            constants.FLAVORS)
        plugin = directory.get_plugin(constants.FLAVORS)
        for collection_name in apidef.SUB_RESOURCE_ATTRIBUTE_MAP:
            # Special handling needed for sub-resources with 'y' ending
            # (e.g. proxies -> proxy)
            resource_name = collection_name[:-1]
            parent = apidef.SUB_RESOURCE_ATTRIBUTE_MAP[collection_name].get(
                'parent')
            params = apidef.SUB_RESOURCE_ATTRIBUTE_MAP[collection_name].get(
                'parameters')

            controller = base.create_resource(collection_name, resource_name,
                                              plugin, params,
                                              allow_bulk=True,
                                              parent=parent)

            resource = extensions.ResourceExtension(
                collection_name,
                controller, parent,
                path_prefix=apidef.API_PREFIX,
                attr_map=params)
            resources.append(resource)

        return resources
