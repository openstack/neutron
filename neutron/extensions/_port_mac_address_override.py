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

# TODO(gibi): remove this when the neutron-lib change
# https://review.opendev.org/c/openstack/neutron-lib/+/831935 merged and
# released

NAME = 'Neutron Port MAC address override'
ALIAS = 'port-mac-override'
DESCRIPTION = (
    "Allow overriding the MAC address of a direct-physical Port via the "
    "active binding profile")

UPDATED_TIMESTAMP = "2022-03-18T10:00:00-00:00"

RESOURCE_ATTRIBUTE_MAP = {}

IS_SHIM_EXTENSION = True
IS_STANDARD_ATTR_EXTENSION = False
SUB_RESOURCE_ATTRIBUTE_MAP = {}
ACTION_MAP = {}
REQUIRED_EXTENSIONS = []
OPTIONAL_EXTENSIONS = []
ACTION_STATUS = {}
