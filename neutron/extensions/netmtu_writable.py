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
from neutron_lib.api.definitions import network
from neutron_lib.api.definitions import network_mtu
from neutron_lib.api import extensions


#TODO(ihrachys) migrate api definition to neutron-lib

MTU = 'mtu'

RESOURCE_ATTRIBUTE_MAP = {
    network.COLLECTION_NAME: {
        MTU: {'allow_post': True, 'allow_put': True, 'is_visible': True,
              'validate': {'type:non_negative': None}, 'default': 0,
              'convert_to': converters.convert_to_int},
    },
}


class Netmtu_writable(extensions.ExtensionDescriptor):
    """Extension class supporting writable network MTU."""

    @classmethod
    def get_name(cls):
        return 'Network MTU (writable)'

    @classmethod
    def get_alias(cls):
        return 'net-mtu-writable'

    @classmethod
    def get_description(cls):
        return 'Provides a writable MTU attribute for a network resource.'

    @classmethod
    def get_updated(cls):
        return '2017-07-12T00:00:00-00:00'

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}

    def get_required_extensions(self):
        return [network_mtu.ALIAS]
