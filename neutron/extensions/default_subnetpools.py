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
from neutron_lib.api.definitions import subnet as subnet_def
from neutron_lib.api import extensions
from neutron_lib import constants


EXTENDED_ATTRIBUTES_2_0 = {
    subnet_def.COLLECTION_NAME: {
        'use_default_subnetpool': {'allow_post': True,
                                   'allow_put': False,
                                   'default': False,
                                   'convert_to': converters.convert_to_boolean,
                                   'is_visible': False, },
    },
}


class Default_subnetpools(extensions.ExtensionDescriptor):
    """Extension class supporting default subnetpools."""

    @classmethod
    def get_name(cls):
        return "Default Subnetpools"

    @classmethod
    def get_alias(cls):
        return "default-subnetpools"

    @classmethod
    def get_description(cls):
        return "Provides ability to mark and use a subnetpool as the default"

    @classmethod
    def get_updated(cls):
        return "2016-02-18T18:00:00-00:00"

    def get_required_extensions(self):
        return [constants.SUBNET_ALLOCATION_EXT_ALIAS]

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
