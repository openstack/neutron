#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

from neutron_lib.api.definitions import \
    security_groups_default_statefulness as apidef
from neutron_lib.api import extensions as api_extensions
from neutron_lib.plugins import directory

from neutron.api import extensions
from neutron.api.v2 import base


class Security_groups_default_statefulness(
        api_extensions.APIExtensionDescriptor):

    api_definition = apidef

    @classmethod
    def get_resources(cls):
        plugin = directory.get_plugin()
        collection_name = apidef.COLLECTION_NAME.replace('_', '-')
        params = apidef.RESOURCE_ATTRIBUTE_MAP.get(
            apidef.COLLECTION_NAME, dict())
        controller = base.create_resource(
            apidef.COLLECTION_NAME,
            apidef.RESOURCE_NAME,
            plugin, params,
            allow_pagination=True,
            allow_sorting=True)

        ex = extensions.ResourceExtension(collection_name, controller,
                                          attr_map=params)
        return [ex]
