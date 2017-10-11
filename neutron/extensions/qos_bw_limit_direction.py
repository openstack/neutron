# Copyright (c) 2017 OVH SAS
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

from neutron_lib.api.definitions import qos as qos_apidef
from neutron_lib.api import extensions as api_extensions
from neutron_lib import constants as common_constants


# The name of the extension.
NAME = "Direction for QoS bandwidth limit rule"

# The alias of the extension.
ALIAS = "qos-bw-limit-direction"

# The description of the extension.
DESCRIPTION = ("Allow to configure QoS bandwidth limit rule with specific "
               "direction: ingress or egress")

# The list of required extensions.
REQUIRED_EXTENSIONS = [qos_apidef.ALIAS]

# The list of optional extensions.
OPTIONAL_EXTENSIONS = None

# The resource attribute map for the extension.
SUB_RESOURCE_ATTRIBUTE_MAP = {
    qos_apidef.BANDWIDTH_LIMIT_RULES: {
        'parameters': {
            'direction': {
                'allow_post': True,
                'allow_put': True,
                'is_visible': True,
                'default': common_constants.EGRESS_DIRECTION,
                'validate': {
                    'type:values': common_constants.VALID_DIRECTIONS}}}
    }
}


class Qos_bw_limit_direction(api_extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return NAME

    @classmethod
    def get_alias(cls):
        return ALIAS

    @classmethod
    def get_description(cls):
        return DESCRIPTION

    @classmethod
    def get_updated(cls):
        return "2017-04-10T10:00:00-00:00"

    def get_required_extensions(self):
        return REQUIRED_EXTENSIONS or []

    def get_optional_extensions(self):
        return OPTIONAL_EXTENSIONS or []

    def get_extended_resources(self, version):
        if version == "2.0":
            return SUB_RESOURCE_ATTRIBUTE_MAP
        else:
            return {}
