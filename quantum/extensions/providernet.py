# Copyright (c) 2012 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from quantum.api.v2 import attributes

NETWORK_TYPE = 'provider:network_type'
PHYSICAL_NETWORK = 'provider:physical_network'
SEGMENTATION_ID = 'provider:segmentation_id'

NETWORK_TYPE_VALUES = ['flat', 'gre', 'local', 'vlan']

EXTENDED_ATTRIBUTES_2_0 = {
    'networks': {
        NETWORK_TYPE: {'allow_post': True, 'allow_put': True,
                       'validate': {'type:values': NETWORK_TYPE_VALUES},
                       'default': attributes.ATTR_NOT_SPECIFIED,
                       'is_visible': True},
        PHYSICAL_NETWORK: {'allow_post': True, 'allow_put': True,
                           'default': attributes.ATTR_NOT_SPECIFIED,
                           'is_visible': True},
        SEGMENTATION_ID: {'allow_post': True, 'allow_put': True,
                          'convert_to': int,
                          'default': attributes.ATTR_NOT_SPECIFIED,
                          'is_visible': True},
    }
}


class Providernet(object):
    """Extension class supporting provider networks.

    This class is used by quantum's extension framework to make
    metadata about the provider network extension available to
    clients. No new resources are defined by this extension. Instead,
    the existing network resource's request and response messages are
    extended with attributes in the provider namespace.

    To create a provider VLAN network using the CLI with admin rights:

       (shell) net-create --tenant_id <tenant-id> <net-name> \
       --provider:network_type vlan \
       --provider:physical_network <physical-net> \
       --provider:segmentation_id <vlan-id>

    With admin rights, network dictionaries returned from CLI commands
    will also include provider attributes.
    """

    @classmethod
    def get_name(cls):
        return "Provider Network"

    @classmethod
    def get_alias(cls):
        return "provider"

    @classmethod
    def get_description(cls):
        return "Expose mapping of virtual networks to physical networks"

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/provider/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2012-09-07T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
