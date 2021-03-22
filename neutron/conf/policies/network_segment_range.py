# Copyright (c) 2019 Intel Corporation.
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
#

from oslo_log import versionutils
from oslo_policy import policy

from neutron.conf.policies import base

DEPRECATED_REASON = """
The network segment range API now supports system scope and default roles.
"""

COLLECTION_PATH = '/network_segment_ranges'
RESOURCE_PATH = '/network_segment_ranges/{id}'


rules = [
    policy.DocumentedRuleDefault(
        name='create_network_segment_range',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Create a network segment range',
        operations=[
            {
                'method': 'POST',
                'path': COLLECTION_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='create_network_segment_range',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_network_segment_range',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description='Get a network segment range',
        operations=[
            {
                'method': 'GET',
                'path': COLLECTION_PATH,
            },
            {
                'method': 'GET',
                'path': RESOURCE_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='get_network_segment_range',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_network_segment_range',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Update a network segment range',
        operations=[
            {
                'method': 'PUT',
                'path': RESOURCE_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='update_network_segment_range',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='delete_network_segment_range',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Delete a network segment range',
        operations=[
            {
                'method': 'DELETE',
                'path': RESOURCE_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_network_segment_range',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
]


def list_rules():
    return rules
