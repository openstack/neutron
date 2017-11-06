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

from neutron_lib.api.definitions import router_availability_zone as apidef
from neutron_lib.api import extensions
import six


class Router_availability_zone(extensions.APIExtensionDescriptor):
    """Router availability zone extension."""

    api_definition = apidef


@six.add_metaclass(abc.ABCMeta)
class RouterAvailabilityZonePluginBase(object):

    @abc.abstractmethod
    def get_router_availability_zones(self, router):
        """Return availability zones which a router belongs to."""
