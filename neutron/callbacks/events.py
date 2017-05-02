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

# NOTE(boden): This module will be removed soon; use neutron-lib callbacks

# String literals representing events associated to data store operations
BEFORE_CREATE = 'before_create'
BEFORE_READ = 'before_read'
BEFORE_UPDATE = 'before_update'
BEFORE_DELETE = 'before_delete'

PRECOMMIT_CREATE = 'precommit_create'
PRECOMMIT_UPDATE = 'precommit_update'
PRECOMMIT_DELETE = 'precommit_delete'

AFTER_CREATE = 'after_create'
AFTER_READ = 'after_read'
AFTER_UPDATE = 'after_update'
AFTER_DELETE = 'after_delete'

# String literals representing events associated to API operations
BEFORE_RESPONSE = 'before_response'
AFTER_REQUEST = 'after_request'

# String literals representing events associated to process operations
BEFORE_INIT = 'before_init'
BEFORE_SPAWN = 'before_spawn'  # sent per process
AFTER_SPAWN = 'after_spawn'  # sent per process
AFTER_INIT = 'after_init'  # sent per worker

# String literals representing events associated to error conditions
ABORT_CREATE = 'abort_create'
ABORT_READ = 'abort_read'
ABORT_UPDATE = 'abort_update'
ABORT_DELETE = 'abort_delete'

ABORT = 'abort_'
BEFORE = 'before_'
PRECOMMIT = 'precommit_'

OVS_RESTARTED = 'ovs_restarted'
