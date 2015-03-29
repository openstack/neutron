# Copyright (c) 2012 OpenStack Foundation.
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

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.common import exceptions as n_exc


NETWORK_TYPE = 'provider:network_type'
PHYSICAL_NETWORK = 'provider:physical_network'
SEGMENTATION_ID = 'provider:segmentation_id'
ATTRIBUTES = (NETWORK_TYPE, PHYSICAL_NETWORK, SEGMENTATION_ID)

# Common definitions for maximum string field length
NETWORK_TYPE_MAX_LEN = 32
PHYSICAL_NETWORK_MAX_LEN = 64

EXTENDED_ATTRIBUTES_2_0 = {
    'networks': {
        NETWORK_TYPE: {'allow_post': True, 'allow_put': True,
                       'validate': {'type:string': NETWORK_TYPE_MAX_LEN},
                       'default': attributes.ATTR_NOT_SPECIFIED,
                       'enforce_policy': True,
                       'is_visible': True},
        PHYSICAL_NETWORK: {'allow_post': True, 'allow_put': True,
                           'validate': {'type:string':
                                        PHYSICAL_NETWORK_MAX_LEN},
                           'default': attributes.ATTR_NOT_SPECIFIED,
                           'enforce_policy': True,
                           'is_visible': True},
        SEGMENTATION_ID: {'allow_post': True, 'allow_put': True,
                          'convert_to': attributes.convert_to_int,
                          'enforce_policy': True,
                          'default': attributes.ATTR_NOT_SPECIFIED,
                          'is_visible': True},
    }
}


def _raise_if_updates_provider_attributes(attrs):
    """Raise exception if provider attributes are present.

    This method is used for plugins that do not support
    updating provider networks.
    """
    if any(attributes.is_attr_set(attrs.get(a)) for a in ATTRIBUTES):
        msg = _("Plugin does not support updating provider attributes")
        raise n_exc.InvalidInput(error_message=msg)


class Providernet(extensions.ExtensionDescriptor):
    """Extension class supporting provider networks.

    This class is used by neutron's extension framework to make
    metadata about the provider network extension available to
    clients. No new resources are defined by this extension. Instead,
    the existing network resource's request and response messages are
    extended with attributes in the provider namespace.

    With admin rights, network dictionaries returned will also include
    provider attributes.
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
