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
TODO(hjensas): This module should be deleted once neutron-lib containing
Change-Id: Ibd1b565a04a6d979b6e56ca5469af644894d6b4c is released.
"""

from neutron_lib.api.definitions import segment


ALIAS = 'segments-peer-subnet-host-routes'
IS_SHIM_EXTENSION = True
IS_STANDARD_ATTR_EXTENSION = False
NAME = 'Segments peer-subnet host routes'
DESCRIPTION = 'Add host routes to subnets on a routed network (segments)'
UPDATED_TIMESTAMP = '2018-06-12T10:00:00-00:00'
RESOURCE_ATTRIBUTE_MAP = {}
SUB_RESOURCE_ATTRIBUTE_MAP = {}
ACTION_MAP = {}
REQUIRED_EXTENSIONS = [segment.ALIAS]
OPTIONAL_EXTENSIONS = []
ACTION_STATUS = {}
