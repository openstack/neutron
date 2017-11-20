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
https://review.openstack.org/#/c/525284/ change is released.
"""

# The alias of the extension.
ALIAS = 'ip-substring-filtering'

# Whether or not this extension is simply signaling behavior to the user
# or it actively modifies the attribute map.
IS_SHIM_EXTENSION = True

# Whether the extension is marking the adoption of standardattr model for
# legacy resources, or introducing new standardattr attributes. False or
# None if the standardattr model is adopted since the introduction of
# resource extension.
# If this is True, the alias for the extension should be prefixed with
# 'standard-attr-'.
IS_STANDARD_ATTR_EXTENSION = False

# The name of the extension.
NAME = 'IP address substring filtering'

# The description of the extension.
DESCRIPTION = "Provides IP address substring filtering when listing ports"

# A timestamp of when the extension was introduced.
UPDATED_TIMESTAMP = "2017-11-28T09:00:00-00:00"

# The resource attribute map for the extension.
RESOURCE_ATTRIBUTE_MAP = {
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
REQUIRED_EXTENSIONS = [
]

# The list of optional extensions.
OPTIONAL_EXTENSIONS = [
]
