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
https://review.openstack.org/#/c/534882/ change is released.
"""

from neutron_lib.api.definitions import l3
from neutron_lib import constants


PORT_DETAILS = 'port_details'

ALIAS = 'fip-port-details'
IS_SHIM_EXTENSION = False
IS_STANDARD_ATTR_EXTENSION = False
NAME = 'Floating IP Port Details Extension'
DESCRIPTION = 'Add port_details attribute to Floating IP resource'
UPDATED_TIMESTAMP = '2018-04-09T10:00:00-00:00'
RESOURCE_ATTRIBUTE_MAP = {
    l3.FLOATINGIPS: {
        PORT_DETAILS: {
            'allow_post': False, 'allow_put': False,
            'default': constants.ATTR_NOT_SPECIFIED,
            'is_visible': True
        }
    }
}
SUB_RESOURCE_ATTRIBUTE_MAP = {}
ACTION_MAP = {}
REQUIRED_EXTENSIONS = [l3.ALIAS]
OPTIONAL_EXTENSIONS = []
ACTION_STATUS = {}
