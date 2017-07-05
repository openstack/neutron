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

from neutron_lib.api.definitions import subnet as subnet_def
from neutron_lib.api import extensions
from neutron_lib.api import validators
from neutron_lib import constants
from neutron_lib import exceptions
import six
import webob.exc

from neutron._i18n import _


# List for service plugins to register their own prefixes
valid_prefixes = []


class InvalidSubnetServiceType(exceptions.InvalidInput):
    message = _("Subnet service type %(service_type)s does not correspond "
                "to a valid device owner.")


class InvalidInputSubnetServiceType(exceptions.InvalidInput):
    message = _("Subnet service type %(service_type)s is not a string.")


def _validate_subnet_service_types(service_types, valid_values=None):
    if service_types:
        if not isinstance(service_types, list):
            raise webob.exc.HTTPBadRequest(
                _("Subnet service types must be a list."))

        prefixes = valid_prefixes
        # Include standard prefixes
        prefixes += list(constants.DEVICE_OWNER_PREFIXES)
        prefixes += constants.DEVICE_OWNER_COMPUTE_PREFIX

        for service_type in service_types:
            if not isinstance(service_type, six.text_type):
                raise InvalidInputSubnetServiceType(service_type=service_type)
            elif not service_type.startswith(tuple(prefixes)):
                raise InvalidSubnetServiceType(service_type=service_type)


validators.add_validator('type:validate_subnet_service_types',
                         _validate_subnet_service_types)


EXTENDED_ATTRIBUTES_2_0 = {
    subnet_def.COLLECTION_NAME: {
        'service_types': {'allow_post': True,
                          'allow_put': True,
                          'default': constants.ATTR_NOT_SPECIFIED,
                          'validate': {'type:validate_subnet_service_types':
                                      None},
                          'is_visible': True, },
    },
}


class Subnet_service_types(extensions.ExtensionDescriptor):
    """Extension class supporting subnet service types."""

    @classmethod
    def get_name(cls):
        return "Subnet service types"

    @classmethod
    def get_alias(cls):
        return "subnet-service-types"

    @classmethod
    def get_description(cls):
        return "Provides ability to set the subnet service_types field"

    @classmethod
    def get_updated(cls):
        return "2016-03-15T18:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
