# Copyright (c) 2016 Hewlett Packard Enterprise Development Company, L.P.
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

from neutron_lib.api.definitions import port as port_def
from neutron_lib.api import extensions


IP_ALLOCATION = 'ip_allocation'
IP_ALLOCATION_IMMEDIATE = 'immediate'
IP_ALLOCATION_DEFERRED = 'deferred'
IP_ALLOCATION_NONE = 'none'

# Attribute Map
RESOURCE_ATTRIBUTE_MAP = {
    port_def.COLLECTION_NAME: {
        IP_ALLOCATION: {'allow_post': False,
                        'allow_put': False,
                        'is_visible': True, },
    },
}


class Ip_allocation(extensions.ExtensionDescriptor):
    """Extension indicates when ports use deferred or no IP allocation."""

    @classmethod
    def get_name(cls):
        return "IP Allocation"

    @classmethod
    def get_alias(cls):
        return "ip_allocation"

    @classmethod
    def get_description(cls):
        return "IP allocation extension."

    @classmethod
    def get_updated(cls):
        return "2016-06-10T23:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}
