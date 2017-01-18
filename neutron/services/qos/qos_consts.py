# Copyright (c) 2015 Red Hat Inc.
# All rights reserved.
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

RULE_TYPE_BANDWIDTH_LIMIT = 'bandwidth_limit'
RULE_TYPE_DSCP_MARKING = 'dscp_marking'
RULE_TYPE_MINIMUM_BANDWIDTH = 'minimum_bandwidth'
VALID_RULE_TYPES = [RULE_TYPE_BANDWIDTH_LIMIT,
                    RULE_TYPE_DSCP_MARKING,
                    RULE_TYPE_MINIMUM_BANDWIDTH,
                    ]

# Names of rules' attributes
MAX_KBPS = "max_kbps"
MAX_BURST = "max_burst_kbps"
MIN_KBPS = "min_kbps"
DIRECTION = "direction"
DSCP_MARK = "dscp_mark"

QOS_POLICY_ID = 'qos_policy_id'

QOS_PLUGIN = 'qos_plugin'

# NOTE(slaweq): Value used to calculate burst value for egress bandwidth limit
# if burst is not given by user. In such case burst value will be calculated
# as 80% of bw_limit to ensure that at least limits for TCP traffic will work
# fine.
DEFAULT_BURST_RATE = 0.8

# Method names for QoSDriver
PRECOMMIT_POSTFIX = '_precommit'
CREATE_POLICY = 'create_policy'
CREATE_POLICY_PRECOMMIT = CREATE_POLICY + PRECOMMIT_POSTFIX
UPDATE_POLICY = 'update_policy'
UPDATE_POLICY_PRECOMMIT = UPDATE_POLICY + PRECOMMIT_POSTFIX
DELETE_POLICY = 'delete_policy'
DELETE_POLICY_PRECOMMIT = DELETE_POLICY + PRECOMMIT_POSTFIX

QOS_CALL_METHODS = (
    CREATE_POLICY,
    CREATE_POLICY_PRECOMMIT,
    UPDATE_POLICY,
    UPDATE_POLICY_PRECOMMIT,
    DELETE_POLICY,
    DELETE_POLICY_PRECOMMIT, )
