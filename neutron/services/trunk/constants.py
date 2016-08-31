# All Rights Reserved.
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


# Valid trunk statuses

# The trunk is happy, yay!
# A trunk remains in ACTIVE state when updates like name or admin_status_up
# occur. It goes back to ACTIVE state from other states (e.g. BUILD) when
# logical and physical resource provisioning has completed successfully. The
# attribute ADMIN_STATE_UP is not to be confused with STATUS: the former
# indicates whether a trunk can be managed. If a trunk has admin_state_up
# equal to false, the trunk plugin will reject any user request to manage
# the trunk resources (i.e. adding/removing sub-ports). ACTIVE_STATUS
# reflects the provisioning state of logical and physical resources associated
# with the trunk.
ACTIVE_STATUS = 'ACTIVE'

# The server has acknowledged the user request: a user has asked to either
# create a trunk or add/remove resources to a trunk, and the plugin has
# created/updated the logical resource. The request has been passed along
# to a backend, and the physical resources associated to the trunk are
# in the process of being provisioned. A trunk is in DOWN state any time
# the physical resources have been deprovisioned due to a system event,
# such as instance deletion. In such a situation, the logical resource
# exists but it has no physical resources associated with it.
DOWN_STATUS = 'DOWN'

# A driver/backend has acknowledged the server request: once the server
# notifies the driver/backend, a trunk is in BUILD state while the
# backend provisions the trunk resources.
BUILD_STATUS = 'BUILD'

# Should any temporary system failure occur during the provisioning process,
# a trunk is in DEGRADED state. This means that the trunk was only
# partially provisioned, and only a subset of the subports were added
# successfully to the trunk. The operation of removing/adding the faulty
# subports may be attempted as a recovery measure.
DEGRADED_STATUS = 'DEGRADED'

# Due to unforeseen circumstances, the user request has led to a conflict, and
# the trunk cannot be provisioned correctly for a subset of subports. For
# instance, a subport belonging to a network might not be compatible with
# the current trunk configuration, or the binding process leads to a persistent
# failure. Removing the 'offending' resource may be attempted as a recovery
# measure, but readding it to the trunk should lead to the same error
# condition. A trunk in ERROR status should be brought back to a sane status
# (i.e. any state except ERROR state) before attempting to add more subports,
# therefore requests of adding more subports must be rejected to avoid
# cascading errors.
ERROR_STATUS = 'ERROR'


# String literals for identifying trunk resources
PARENT_PORT = 'parent_port'
SUBPORTS = 'subports'
TRUNK = 'trunk'
TRUNK_PLUGIN = 'trunk_plugin'


# String literals for segmentation types
VLAN = 'vlan'
