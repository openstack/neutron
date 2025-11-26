#  Copyright 2025 Samsung SDS. All Rights Reserved
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
#  implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from neutron_lib.api.definitions import network_ip_availability as base_apidef
from neutron_lib.api.definitions import network_ip_availability_details as \
    details_apidef
from neutron_lib.api import extensions as api_extensions

from neutron.api import extensions
from neutron.api.v2 import base
from neutron.services.network_ip_availability import plugin


class Network_ip_availability_details(api_extensions.APIExtensionDescriptor):
    """Extension class supporting
    detailed network ip availability information.
    """
    api_definition = details_apidef

    @classmethod
    def get_resources(cls):
        """Returns Extended Resource for service type management."""
        resource_attributes = (
            base_apidef.RESOURCE_ATTRIBUTE_MAP)[base_apidef.RESOURCE_PLURAL]
        resource_attributes.update(details_apidef.RESOURCE_ATTRIBUTE_MAP)
        controller = base.create_resource(
            base_apidef.RESOURCE_PLURAL,
            base_apidef.RESOURCE_NAME,
            plugin.NetworkIPAvailabilityPlugin.get_instance(),
            resource_attributes,
            allow_pagination=True,
            allow_sorting=True,
        )
        return [extensions.ResourceExtension(base_apidef.COLLECTION_NAME,
                                             controller,
                                             attr_map=resource_attributes)]
