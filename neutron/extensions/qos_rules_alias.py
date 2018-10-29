# Copyright (c) 2018 Huawei Technology, Inc.  All rights reserved.
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

from neutron_lib.api.definitions import qos_rules_alias as apidef
from neutron_lib.api import extensions as api_extensions
from neutron_lib.plugins import constants

from neutron.api.v2 import resource_helper


class Qos_rules_alias(api_extensions.APIExtensionDescriptor):
    """Extension class supporting QoS rules alias API resources."""
    api_definition = apidef

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plural_mappings = resource_helper.build_plural_mappings(
                {}, apidef.RESOURCE_ATTRIBUTE_MAP)

        return resource_helper.build_resource_info(
            plural_mappings,
            apidef.RESOURCE_ATTRIBUTE_MAP,
            constants.QOS,
            translate_name=True,
            allow_bulk=True)
