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

from neutron_lib.api import extensions

from neutron.extensions import security_groups_shared_filtering_lib


class Security_groups_shared_filtering(extensions.APIExtensionDescriptor):
    """Extension class supporting filtering SGs depend on the shared field."""

    api_definition = security_groups_shared_filtering_lib
