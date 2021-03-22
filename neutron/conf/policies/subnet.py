#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

from oslo_log import versionutils
from oslo_policy import policy

from neutron.conf.policies import base

DEPRECATED_REASON = (
    "The subnet API now supports system scope and default roles.")

COLLECTION_PATH = '/subnets'
RESOURCE_PATH = '/subnets/{id}'

ACTION_POST = [
    {'method': 'POST', 'path': COLLECTION_PATH},
]
ACTION_PUT = [
    {'method': 'PUT', 'path': RESOURCE_PATH},
]
ACTION_DELETE = [
    {'method': 'DELETE', 'path': RESOURCE_PATH},
]
ACTION_GET = [
    {'method': 'GET', 'path': COLLECTION_PATH},
    {'method': 'GET', 'path': RESOURCE_PATH},
]


rules = [
    policy.DocumentedRuleDefault(
        name='create_subnet',
        check_str=base.policy_or(
            base.SYSTEM_ADMIN_OR_PROJECT_MEMBER,
            base.RULE_NET_OWNER),
        scope_types=['system', 'project'],
        description='Create a subnet',
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_subnet',
            check_str=base.RULE_ADMIN_OR_NET_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_subnet:segment_id',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description=(
            'Specify ``segment_id`` attribute when creating a subnet'
        ),
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_subnet:segment_id',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_subnet:service_types',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description=(
            'Specify ``service_types`` attribute when creating a subnet'
        ),
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_subnet:service_types',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_subnet',
        check_str=base.policy_or(
            base.SYSTEM_OR_PROJECT_READER,
            'rule:shared'),
        scope_types=['system', 'project'],
        description='Get a subnet',
        operations=ACTION_GET,
        deprecated_rule=policy.DeprecatedRule(
            name='get_subnet',
            check_str=base.policy_or(
                base.RULE_ADMIN_OR_OWNER,
                'rule:shared'),
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_subnet:segment_id',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description='Get ``segment_id`` attribute of a subnet',
        operations=ACTION_GET,
        deprecated_rule=policy.DeprecatedRule(
            name='get_subnet:segment_id',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_subnet',
        check_str=base.policy_or(
            base.SYSTEM_ADMIN_OR_PROJECT_MEMBER,
            base.RULE_NET_OWNER),
        scope_types=['system', 'project'],
        description='Update a subnet',
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_subnet',
            check_str=base.RULE_ADMIN_OR_NET_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_subnet:segment_id',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Update ``segment_id`` attribute of a subnet',
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_subnet:segment_id',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_subnet:service_types',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Update ``service_types`` attribute of a subnet',
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_subnet:service_types',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='delete_subnet',
        check_str=base.policy_or(
            base.SYSTEM_ADMIN_OR_PROJECT_MEMBER,
            base.RULE_NET_OWNER),
        scope_types=['system', 'project'],
        description='Delete a subnet',
        operations=ACTION_DELETE,
        deprecated_rule=policy.DeprecatedRule(
            name='delete_subnet',
            check_str=base.RULE_ADMIN_OR_NET_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
]


def list_rules():
    return rules
