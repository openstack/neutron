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

from neutron_lib.api.definitions import port_mac_address_regenerate
from neutron_lib.api import extensions as api_extensions


class Port_mac_address_regenerate(api_extensions.APIExtensionDescriptor):
    """Extension to support port MAC address regeneration"""

    api_definition = port_mac_address_regenerate
