# Copyright 2016 GoDaddy.
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

from neutron_lib.api import extensions as api_extensions

import neutron.api.extensions as extensions
import neutron.api.v2.base as base
import neutron.services.network_ip_availability.plugin as plugin

RESOURCE_NAME = "network_ip_availability"
RESOURCE_PLURAL = "network_ip_availabilities"
COLLECTION_NAME = RESOURCE_PLURAL.replace('_', '-')
EXT_ALIAS = RESOURCE_NAME.replace('_', '-')

RESOURCE_ATTRIBUTE_MAP = {
    RESOURCE_PLURAL: {
        'network_id': {'allow_post': False, 'allow_put': False,
                       'is_visible': True},
        'network_name': {'allow_post': False, 'allow_put': False,
                         'is_visible': True},
        'tenant_id': {'allow_post': False, 'allow_put': False,
                      'is_visible': True},
        'total_ips': {'allow_post': False, 'allow_put': False,
                      'is_visible': True},
        'used_ips': {'allow_post': False, 'allow_put': False,
                     'is_visible': True},
        'subnet_ip_availability': {'allow_post': False, 'allow_put': False,
                                   'is_visible': True},
        # TODO(wwriverrat) Make composite attribute for subnet_ip_availability
    }
}


class Network_ip_availability(api_extensions.ExtensionDescriptor):
    """Extension class supporting network ip availability information."""

    @classmethod
    def get_name(cls):
        return "Network IP Availability"

    @classmethod
    def get_alias(cls):
        return EXT_ALIAS

    @classmethod
    def get_description(cls):
        return "Provides IP availability data for each network and subnet."

    @classmethod
    def get_updated(cls):
        return "2015-09-24T00:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Extended Resource for service type management."""
        resource_attributes = RESOURCE_ATTRIBUTE_MAP[RESOURCE_PLURAL]
        controller = base.create_resource(
            RESOURCE_PLURAL,
            RESOURCE_NAME,
            plugin.NetworkIPAvailabilityPlugin.get_instance(),
            resource_attributes)
        return [extensions.ResourceExtension(COLLECTION_NAME,
                                             controller,
                                             attr_map=resource_attributes)]

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}
