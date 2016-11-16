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

import abc

from neutron_lib.api import extensions as api_extensions
from neutron_lib.api import validators
from neutron_lib import exceptions
from neutron_lib.plugins import directory
from oslo_serialization import jsonutils
import six

from neutron._i18n import _
from neutron.api import extensions
from neutron.api.v2 import base


AZ_HINTS_DB_LEN = 255


# resource independent common methods
def convert_az_list_to_string(az_list):
    return jsonutils.dumps(az_list)


def convert_az_string_to_list(az_string):
    return jsonutils.loads(az_string) if az_string else []


def _validate_availability_zone_hints(data, valid_value=None):
    # syntax check only here. existence of az will be checked later.
    msg = validators.validate_list_of_unique_strings(data)
    if msg:
        return msg
    az_string = convert_az_list_to_string(data)
    if len(az_string) > AZ_HINTS_DB_LEN:
        msg = _("Too many availability_zone_hints specified")
        raise exceptions.InvalidInput(error_message=msg)

validators.add_validator('availability_zone_hints',
                         _validate_availability_zone_hints)

# Attribute Map
RESOURCE_NAME = 'availability_zone'
AVAILABILITY_ZONES = 'availability_zones'
AZ_HINTS = 'availability_zone_hints'
# name: name of availability zone (string)
# resource: type of resource: 'network' or 'router'
# state: state of availability zone: 'available' or 'unavailable'
# It means whether users can use the availability zone.
RESOURCE_ATTRIBUTE_MAP = {
    AVAILABILITY_ZONES: {
        'name': {'is_visible': True},
        'resource': {'is_visible': True},
        'state': {'is_visible': True}
    }
}

EXTENDED_ATTRIBUTES_2_0 = {
    'agents': {
        RESOURCE_NAME: {'allow_post': False, 'allow_put': False,
                        'is_visible': True}
    }
}


class AvailabilityZoneNotFound(exceptions.NotFound):
    message = _("AvailabilityZone %(availability_zone)s could not be found.")


class Availability_zone(api_extensions.ExtensionDescriptor):
    """Availability zone extension."""

    @classmethod
    def get_name(cls):
        return "Availability Zone"

    @classmethod
    def get_alias(cls):
        return "availability_zone"

    @classmethod
    def get_description(cls):
        return "The availability zone extension."

    @classmethod
    def get_updated(cls):
        return "2015-01-01T10:00:00-00:00"

    def get_required_extensions(self):
        return ["agent"]

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plugin = directory.get_plugin()
        params = RESOURCE_ATTRIBUTE_MAP.get(AVAILABILITY_ZONES)
        controller = base.create_resource(AVAILABILITY_ZONES,
                                          RESOURCE_NAME, plugin, params)

        ex = extensions.ResourceExtension(AVAILABILITY_ZONES, controller)

        return [ex]

    def get_extended_resources(self, version):
        if version == "2.0":
            return dict(list(EXTENDED_ATTRIBUTES_2_0.items()) +
                        list(RESOURCE_ATTRIBUTE_MAP.items()))
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class AvailabilityZonePluginBase(object):
    """REST API to operate the Availability Zone."""

    @abc.abstractmethod
    def get_availability_zones(self, context, filters=None, fields=None,
                               sorts=None, limit=None, marker=None,
                               page_reverse=False):
        """Return availability zones which a resource belongs to"""

    @abc.abstractmethod
    def validate_availability_zones(self, context, resource_type,
                                    availability_zones):
        """Verify that the availability zones exist."""
