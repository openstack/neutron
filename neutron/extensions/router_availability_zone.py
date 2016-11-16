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

from neutron_lib.api import extensions
import six

from neutron.extensions import availability_zone as az_ext


EXTENDED_ATTRIBUTES_2_0 = {
    'routers': {
        az_ext.AVAILABILITY_ZONES: {'allow_post': False, 'allow_put': False,
                                    'is_visible': True},
        az_ext.AZ_HINTS: {
                'allow_post': True, 'allow_put': False, 'is_visible': True,
                'validate': {'type:availability_zone_hints': None},
                'default': []}}
}


class Router_availability_zone(extensions.ExtensionDescriptor):
    """Router availability zone extension."""

    @classmethod
    def get_name(cls):
        return "Router Availability Zone"

    @classmethod
    def get_alias(cls):
        return "router_availability_zone"

    @classmethod
    def get_description(cls):
        return "Availability zone support for router."

    @classmethod
    def get_updated(cls):
        return "2015-01-01T10:00:00-00:00"

    def get_required_extensions(self):
        return ["router", "availability_zone"]

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class RouterAvailabilityZonePluginBase(object):

    @abc.abstractmethod
    def get_router_availability_zones(self, router):
        """Return availability zones which a router belongs to."""
