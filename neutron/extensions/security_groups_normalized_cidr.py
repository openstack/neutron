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

from neutron_lib.api.definitions import security_groups_normalized_cidr
from neutron_lib.api import extensions


class Security_groups_normalized_cidr(extensions.APIExtensionDescriptor):
    """Extension class supporting normalized cidr in the SG rules."""

    api_definition = security_groups_normalized_cidr
