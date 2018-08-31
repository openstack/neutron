# (c) Copyright 2017 Hewlett Packard Enterprise Development LP
#
# All Rights Reserved.
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

from neutron_lib.api.definitions import subnet_onboard as subnet_onboard_def
from neutron_lib.api.definitions import subnetpool as subnetpool_def
from neutron_lib.api import extensions

from neutron.api.v2 import resource_helper


class Subnet_onboard(extensions.APIExtensionDescriptor):
    """API extension for subnet onboard."""

    api_definition = subnet_onboard_def

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plural_mappings = resource_helper.build_plural_mappings(
            {}, subnetpool_def.RESOURCE_ATTRIBUTE_MAP)
        return resource_helper.build_resource_info(
            plural_mappings,
            subnetpool_def.RESOURCE_ATTRIBUTE_MAP,
            None,
            action_map=subnet_onboard_def.ACTION_MAP,
            register_quota=True)
