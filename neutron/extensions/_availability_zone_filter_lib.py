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
TODO(hongbin): This module should be deleted once neutron-lib containing
https://review.opendev.org/#/c/577545/ change is released.
"""

from neutron_lib.api.definitions import availability_zone as az


ALIAS = 'availability_zone_filter'
IS_SHIM_EXTENSION = True
IS_STANDARD_ATTR_EXTENSION = False
NAME = 'Availability Zone Filter Extension'
DESCRIPTION = 'Add filter parameters to AvailabilityZone resource'
UPDATED_TIMESTAMP = '2018-06-22T10:00:00-00:00'
RESOURCE_ATTRIBUTE_MAP = {}
SUB_RESOURCE_ATTRIBUTE_MAP = {}
ACTION_MAP = {}
REQUIRED_EXTENSIONS = [
    az.ALIAS
]
OPTIONAL_EXTENSIONS = []
ACTION_STATUS = {}
