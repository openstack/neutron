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

from neutron_lib.api import extensions
from neutron_lib import constants

from neutron._i18n import _


EXTENDED_ATTRIBUTES_2_0 = {
    'networks': {
        'network_extension': {'allow_post': True,
                              'allow_put': True,
                              'default': constants.ATTR_NOT_SPECIFIED,
                              'is_visible': True,
                              'enforce_policy': True},
    },
    'subnets': {
        'subnet_extension': {'allow_post': True,
                             'allow_put': True,
                             'default': constants.ATTR_NOT_SPECIFIED,
                             'is_visible': True,
                             'enforce_policy': True},
    },
    'ports': {
        'port_extension': {'allow_post': True,
                           'allow_put': True,
                           'default': constants.ATTR_NOT_SPECIFIED,
                           'is_visible': True,
                           'enforce_policy': True},
    },
}


class Fake_extension(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "ML2 fake extension"

    @classmethod
    def get_alias(cls):
        return "fake_extension"

    @classmethod
    def get_description(cls):
        return _("Adds test attributes to core resources.")

    @classmethod
    def get_updated(cls):
        return "2014-07-16T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
