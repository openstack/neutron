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

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import base
from neutron.common import exceptions
from neutron import manager


# Attribute Map
RESOURCE_NAME = 'availability_zone'
AVAILABILITY_ZONES = 'availability_zones'
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


class Availability_zone(extensions.ExtensionDescriptor):
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
        my_plurals = [(key, key[:-1]) for key in RESOURCE_ATTRIBUTE_MAP.keys()]
        attr.PLURALS.update(dict(my_plurals))
        plugin = manager.NeutronManager.get_plugin()
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


class AvailabilityZonePluginBase(object):
    """REST API to operate the Availability Zone."""

    @abc.abstractmethod
    def get_availability_zones(self, context, filters=None, fields=None,
                               sorts=None, limit=None, marker=None,
                               page_reverse=False):
        pass

    @abc.abstractmethod
    def validate_availability_zones(self, context, resource_type,
                                    availability_zones):
        pass
