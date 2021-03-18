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


COLLECTION_PATH = '/address-scopes'
RESOURCE_PATH = '/address-scopes/{id}'

DEPRECATION_REASON = (
    "The Address scope API now supports system scope and default roles.")


rules = [
    policy.RuleDefault(
        'shared_address_scopes',
        'field:address_scopes:shared=True',
        'Definition of a shared address scope'
    ),
    policy.DocumentedRuleDefault(
        name='create_address_scope',
        check_str=base.SYSTEM_ADMIN_OR_PROJECT_MEMBER,
        description='Create an address scope',
        operations=[
            {
                'method': 'POST',
                'path': COLLECTION_PATH,
            },
        ],
        scope_types=['system', 'project'],
        deprecated_rule=policy.DeprecatedRule(
            name='create_address_scope',
            check_str=base.RULE_ANY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_address_scope:shared',
        check_str=base.SYSTEM_ADMIN,
        description='Create a shared address scope',
        operations=[
            {
                'method': 'POST',
                'path': COLLECTION_PATH,
            },
        ],
        scope_types=['system', 'project'],
        deprecated_rule=policy.DeprecatedRule(
            name='create_address_scope:shared',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_address_scope',
        check_str=base.policy_or(base.SYSTEM_OR_PROJECT_READER,
                                 'rule:shared_address_scopes'),
        description='Get an address scope',
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
        scope_types=['system', 'project'],
        deprecated_rule=policy.DeprecatedRule(
            name='get_address_scope',
            check_str=base.policy_or(base.RULE_ADMIN_OR_OWNER,
                                     'rule:shared_address_scopes'),
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_address_scope',
        check_str=base.SYSTEM_ADMIN_OR_PROJECT_MEMBER,
        description='Update an address scope',
        operations=[
            {
                'method': 'PUT',
                'path': RESOURCE_PATH,
            },
        ],
        scope_types=['system', 'project'],
        deprecated_rule=policy.DeprecatedRule(
            name='update_address_scope',
            check_str=base.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_address_scope:shared',
        check_str=base.SYSTEM_ADMIN,
        description='Update ``shared`` attribute of an address scope',
        operations=[
            {
                'method': 'PUT',
                'path': RESOURCE_PATH,
            },
        ],
        scope_types=['system', 'project'],
        deprecated_rule=policy.DeprecatedRule(
            name='update_address_scope:shared',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='delete_address_scope',
        check_str=base.SYSTEM_ADMIN_OR_PROJECT_MEMBER,
        description='Delete an address scope',
        operations=[
            {
                'method': 'DELETE',
                'path': RESOURCE_PATH,
            },
        ],
        scope_types=['system', 'project'],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_address_scope',
            check_str=base.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
]


def list_rules():
    return rules
