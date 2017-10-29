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

from neutron_lib.api.definitions import availability_zone as az_def
from neutron_lib.api import extensions as api_extensions
from neutron_lib.plugins import directory
import six

from neutron.api import extensions
from neutron.api.v2 import base


class Availability_zone(api_extensions.APIExtensionDescriptor):
    """Availability zone extension."""
    api_definition = az_def

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plugin = directory.get_plugin()
        params = az_def.RESOURCE_ATTRIBUTE_MAP.get(az_def.COLLECTION_NAME)
        controller = base.create_resource(az_def.COLLECTION_NAME,
                                          az_def.RESOURCE_NAME, plugin, params)

        ex = extensions.ResourceExtension(az_def.COLLECTION_NAME, controller)

        return [ex]


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
