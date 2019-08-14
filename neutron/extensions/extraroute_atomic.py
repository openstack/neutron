# Copyright 2019 Ericsson Software Technology
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

from neutron_lib.api.definitions import extraroute_atomic
from neutron_lib.api import extensions as api_extensions
from neutron_lib.plugins import constants

from neutron.api.v2 import resource_helper


class Extraroute_atomic(api_extensions.APIExtensionDescriptor):
    api_definition = extraroute_atomic

    @classmethod
    def get_resources(cls):
        plural_mappings = resource_helper.build_plural_mappings(
            {}, extraroute_atomic.RESOURCE_ATTRIBUTE_MAP)
        return resource_helper.build_resource_info(
            plural_mappings,
            extraroute_atomic.RESOURCE_ATTRIBUTE_MAP,
            constants.L3,
            action_map=extraroute_atomic.ACTION_MAP)
