# Copyright (c) 2016 ZTE Inc.
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

from neutron_lib.api.definitions import trunk
from neutron_lib.api import extensions

from neutron.api.v2 import resource_helper


class Trunk(extensions.APIExtensionDescriptor):
    """Trunk API extension."""
    api_definition = trunk

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plural_mappings = resource_helper.build_plural_mappings(
            {}, trunk.RESOURCE_ATTRIBUTE_MAP)
        return resource_helper.build_resource_info(
            plural_mappings,
            trunk.RESOURCE_ATTRIBUTE_MAP,
            trunk.ALIAS,
            action_map=trunk.ACTION_MAP,
            register_quota=True)
