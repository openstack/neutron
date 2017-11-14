# Copyright (c) 2017 Intel Corporation.
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

from neutron_lib.api import converters
from neutron_lib.api.definitions import qos as qos_apidef
from neutron_lib.api import extensions


# The alias of the extension.
ALIAS = 'qos-default'

# The name of the extension.
NAME = 'QoS default policy'

# The description of the extension.
DESCRIPTION = 'Expose the QoS default policy per project'

# A timestamp of when the extension was introduced.
TIMESTAMP = '2017-041-06T10:00:00-00:00'

# The list of required extensions.
REQUIRED_EXTENSIONS = [qos_apidef.ALIAS]

# The list of optional extensions.
OPTIONAL_EXTENSIONS = None

# The resource attribute map for the extension.
RESOURCE_ATTRIBUTE_MAP = {
    qos_apidef.POLICIES: {
        'is_default': {'allow_post': True,
                       'allow_put': True,
                       'default': False,
                       'convert_to': converters.convert_to_boolean,
                       'is_visible': True}
    }
}


class Qos_default(extensions.ExtensionDescriptor):

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
        return TIMESTAMP

    def get_required_extensions(self):
        return REQUIRED_EXTENSIONS or []

    def get_optional_extensions(self):
        return OPTIONAL_EXTENSIONS or []

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}
