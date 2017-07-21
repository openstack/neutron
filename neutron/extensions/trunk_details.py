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

from neutron_lib.api.definitions import trunk_details
from neutron_lib.api import extensions


# NOTE(armax): because of the API machinery, this extension must be on
# its own. This aims at providing subport information for ports that
# are parent in a trunk so that consumers of the Neutron API, like Nova
# can efficiently access trunk information for things like metadata or
# config-drive configuration.


class Trunk_details(extensions.APIExtensionDescriptor):
    api_definition = trunk_details
