#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#

from neutron_lib.api import extensions
from neutron_lib import constants


EXTENDED_ATTRIBUTES_2_0 = {
    'routers': {
        'flavor_id': {'allow_post': True, 'allow_put': False,
                      'default': constants.ATTR_NOT_SPECIFIED,
                      'is_visible': True, 'enforce_policy': True}

    }
}


class L3_flavors(extensions.ExtensionDescriptor):
    """Extension class supporting flavors for routers."""

    @classmethod
    def get_name(cls):
        return "Router Flavor Extension"

    @classmethod
    def get_alias(cls):
        return 'l3-flavors'

    @classmethod
    def get_description(cls):
        return "Flavor support for routers."

    @classmethod
    def get_updated(cls):
        return "2016-05-17T00:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}

    def get_required_extensions(self):
        return ["router", "flavors"]
