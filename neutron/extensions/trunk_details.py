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

from neutron_lib import constants

from neutron.api import extensions


# NOTE(armax): because of the API machinery, this extension must be on
# its own. This aims at providing subport information for ports that
# are parent in a trunk so that consumers of the Neutron API, like Nova
# can efficiently access trunk information for things like metadata or
# config-drive configuration.
EXTENDED_ATTRIBUTES_2_0 = {
    'ports': {'trunk_details': {'allow_post': False, 'allow_put': False,
                                'default': constants.ATTR_NOT_SPECIFIED,
                                'is_visible': True,
                                'enforce_policy': True,
                                'required_by_policy': True}},
}


class Trunk_details(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Trunk port details"

    @classmethod
    def get_alias(cls):
        return "trunk-details"

    @classmethod
    def get_description(cls):
        return "Expose trunk port details"

    @classmethod
    def get_updated(cls):
        return "2016-01-01T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
