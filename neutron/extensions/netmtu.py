# Copyright 2015 Openstack Foundation.
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

from neutron.api import extensions


MTU = 'mtu'
EXTENDED_ATTRIBUTES_2_0 = {
    'networks': {
        MTU: {'allow_post': False, 'allow_put': False,
              'is_visible': True},
    },
}


class Netmtu(extensions.ExtensionDescriptor):
    """Extension class supporting network MTU."""

    @classmethod
    def get_name(cls):
        return "Network MTU"

    @classmethod
    def get_alias(cls):
        return "net-mtu"

    @classmethod
    def get_description(cls):
        return "Provides MTU attribute for a network resource."

    @classmethod
    def get_updated(cls):
        return "2015-03-25T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
