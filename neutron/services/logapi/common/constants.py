# Copyright 2017 Fujitsu Limited.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

ACCEPT_EVENT = 'ACCEPT'
DROP_EVENT = 'DROP'
ALL_EVENT = 'ALL'
LOG_EVENTS = [ACCEPT_EVENT, DROP_EVENT, ALL_EVENT]
LOGGING_PLUGIN = 'logging-plugin'

# supported logging types
SECURITY_GROUP = 'security_group'
# TODO(annp): Moving to neutron-lib
SNAT = 'snat'

# target resource types
PORT = 'port'

RPC_NAMESPACE_LOGGING = 'logging-plugin'

# Define for rpc_method_key
LOG_RESOURCE = 'log_resource'

# String literal for identifying log resource
LOGGING = 'log'

# Method names for Logging Driver
PRECOMMIT_POSTFIX = '_precommit'
CREATE_LOG = 'create_log'
CREATE_LOG_PRECOMMIT = CREATE_LOG + PRECOMMIT_POSTFIX
UPDATE_LOG = 'update_log'
UPDATE_LOG_PRECOMMIT = UPDATE_LOG + PRECOMMIT_POSTFIX
DELETE_LOG = 'delete_log'
DELETE_LOG_PRECOMMIT = DELETE_LOG + PRECOMMIT_POSTFIX
# Tell to agent when resources related log_objects update
RESOURCE_UPDATE = 'resource_update'

LOG_CALL_METHODS = (
    CREATE_LOG,
    CREATE_LOG_PRECOMMIT,
    UPDATE_LOG,
    UPDATE_LOG_PRECOMMIT,
    DELETE_LOG,
    DELETE_LOG_PRECOMMIT,
    RESOURCE_UPDATE
)

DIRECTION_IP_PREFIX = {'ingress': 'source_ip_prefix',
                       'egress': 'dest_ip_prefix'}
