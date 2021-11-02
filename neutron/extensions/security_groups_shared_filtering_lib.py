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

# NOTE(hangyang): This file can be removed once the api def is merged
# to neutron-lib https://review.opendev.org/c/openstack/neutron-lib/+/812617

from neutron_lib.api import converters
from neutron_lib import constants


# The alias of the extension.
ALIAS = 'security-groups-shared-filtering'

IS_SHIM_EXTENSION = False

IS_STANDARD_ATTR_EXTENSION = False

# The name of the extension.
NAME = 'Security group filtering on the shared field'

# The description of the extension.
DESCRIPTION = "Support filtering security groups on the shared field"

# A timestamp of when the extension was introduced.
UPDATED_TIMESTAMP = "2021-10-05T09:00:00-00:00"

# The resource attribute map for the extension.
RESOURCE_ATTRIBUTE_MAP = {
    'security_groups': {
        constants.SHARED: {
            'allow_post': False,
            'allow_put': False,
            'convert_to': converters.convert_to_boolean,
            'is_visible': True,
            'is_filter': True,
            'required_by_policy': True,
            'enforce_policy': True}
    }
}

# The subresource attribute map for the extension.
SUB_RESOURCE_ATTRIBUTE_MAP = {
}

# The action map.
ACTION_MAP = {
}

# The action status.
ACTION_STATUS = {
}

# The list of required extensions.
REQUIRED_EXTENSIONS = ['rbac-security-groups']

# The list of optional extensions.
OPTIONAL_EXTENSIONS = [
]
