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

"""
TODO(mlavalle): This module should be deleted once neutron-lib containing
https://review.openstack.org/#/c/564381/ change is released.
"""

from neutron_lib.api.definitions import portbindings_extended


PORT_BINDING = portbindings_extended.RESOURCE_NAME

ACTIVATE = 'activate'
DEACTIVATE = 'deactivate'
