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

DEPRECATED_REASON = """
The RBAC API now supports system scope and default roles.
"""


COLLECTION_PATH = '/rbac-policies'
RESOURCE_PATH = '/rbac-policies/{id}'


rules = [
    policy.RuleDefault(
        name='restrict_wildcard',
        check_str=base.policy_or(
            '(not field:rbac_policy:target_tenant=*)',
            base.RULE_ADMIN_ONLY),
        description='Definition of a wildcard target_tenant'),

    policy.DocumentedRuleDefault(
        name='create_rbac_policy',
        check_str=base.SYSTEM_ADMIN_OR_PROJECT_MEMBER,
        scope_types=['system', 'project'],
        description='Create an RBAC policy',
        operations=[
            {
                'method': 'POST',
                'path': COLLECTION_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='create_rbac_policy',
            check_str=base.RULE_ANY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_rbac_policy:target_tenant',
        check_str=base.policy_or(
            base.SYSTEM_ADMIN,
            'rule:restrict_wildcard'),
        description='Specify ``target_tenant`` when creating an RBAC policy',
        operations=[
            {
                'method': 'POST',
                'path': COLLECTION_PATH,
            },
        ],
        scope_types=['system', 'project'],
        deprecated_rule=policy.DeprecatedRule(
            name='create_rbac_policy:target_tenant',
            check_str='rule:restrict_wildcard',
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_rbac_policy',
        check_str=base.SYSTEM_ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project', 'system'],
        description='Update an RBAC policy',
        operations=[
            {
                'method': 'PUT',
                'path': RESOURCE_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='update_rbac_policy',
            check_str=base.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_rbac_policy:target_tenant',
        check_str=base.policy_or(
            base.SYSTEM_ADMIN,
            'rule:restrict_wildcard'),
        description='Update ``target_tenant`` attribute of an RBAC policy',
        operations=[
            {
                'method': 'PUT',
                'path': RESOURCE_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='update_rbac_policy:target_tenant',
            check_str=base.policy_and(
                'rule:restrict_wildcard',
                base.RULE_ADMIN_OR_OWNER),
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY),
        scope_types=['system', 'project'],
    ),
    policy.DocumentedRuleDefault(
        name='get_rbac_policy',
        check_str=base.SYSTEM_OR_PROJECT_READER,
        scope_types=['project', 'system'],
        description='Get an RBAC policy',
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
            name='get_rbac_policy',
            check_str=base.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='delete_rbac_policy',
        check_str=base.SYSTEM_ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project', 'system'],
        description='Delete an RBAC policy',
        operations=[
            {
                'method': 'DELETE',
                'path': RESOURCE_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_rbac_policy',
            check_str=base.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
]


def list_rules():
    return rules
