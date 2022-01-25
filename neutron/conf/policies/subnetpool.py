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
    "The subnet pool API now supports system scope and default roles.")

COLLECTION_PATH = '/subnetpools'
RESOURCE_PATH = '/subnetpools/{id}'
ONBOARD_PATH = '/subnetpools/{id}/onboard_network_subnets'
ADD_PREFIXES_PATH = '/subnetpools/{id}/add_prefixes'
REMOVE_PREFIXES_PATH = '/subnetpools/{id}/remove_prefixes'


rules = [
    policy.RuleDefault(
        name='shared_subnetpools',
        check_str='field:subnetpools:shared=True',
        description='Definition of a shared subnetpool'
    ),
    policy.DocumentedRuleDefault(
        name='create_subnetpool',
        check_str=base.PROJECT_MEMBER,
        scope_types=['project'],
        description='Create a subnetpool',
        operations=[
            {
                'method': 'POST',
                'path': COLLECTION_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='create_subnetpool',
            check_str=base.RULE_ANY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_subnetpool:shared',
        check_str=base.PROJECT_ADMIN,
        scope_types=['project'],
        description='Create a shared subnetpool',
        operations=[
            {
                'method': 'POST',
                'path': COLLECTION_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='create_subnetpool:shared',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_subnetpool:is_default',
        check_str=base.PROJECT_ADMIN,
        scope_types=['project'],
        description=(
            'Specify ``is_default`` attribute when creating a subnetpool'
        ),
        operations=[
            {
                'method': 'POST',
                'path': COLLECTION_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='create_subnetpool:is_default',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_subnetpool',
        check_str=base.policy_or(
            base.PROJECT_READER,
            'rule:shared_subnetpools'
        ),
        scope_types=['project'],
        description='Get a subnetpool',
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
            name='get_subnetpool',
            check_str=base.policy_or(
                base.RULE_ADMIN_OR_OWNER,
                'rule:shared_subnetpools'),
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_subnetpool',
        check_str=base.PROJECT_MEMBER,
        scope_types=['project'],
        description='Update a subnetpool',
        operations=[
            {
                'method': 'PUT',
                'path': RESOURCE_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='update_subnetpool',
            check_str=base.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_subnetpool:is_default',
        check_str=base.PROJECT_ADMIN,
        scope_types=['project'],
        description='Update ``is_default`` attribute of a subnetpool',
        operations=[
            {
                'method': 'PUT',
                'path': RESOURCE_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='update_subnetpool:is_default',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='delete_subnetpool',
        check_str=base.PROJECT_MEMBER,
        scope_types=['project'],
        description='Delete a subnetpool',
        operations=[
            {
                'method': 'DELETE',
                'path': RESOURCE_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_subnetpool',
            check_str=base.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='onboard_network_subnets',
        check_str=base.PROJECT_MEMBER,
        scope_types=['project'],
        description='Onboard existing subnet into a subnetpool',
        operations=[
            {
                'method': 'PUT',
                'path': ONBOARD_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='onboard_network_subnets',
            check_str=base.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='add_prefixes',
        check_str=base.PROJECT_MEMBER,
        scope_types=['project'],
        description='Add prefixes to a subnetpool',
        operations=[
            {
                'method': 'PUT',
                'path': ADD_PREFIXES_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='add_prefixes',
            check_str=base.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='remove_prefixes',
        check_str=base.PROJECT_MEMBER,
        scope_types=['project'],
        description='Remove unallocated prefixes from a subnetpool',
        operations=[
            {
                'method': 'PUT',
                'path': REMOVE_PREFIXES_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='remove_prefixes',
            check_str=base.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
]


def list_rules():
    return rules
