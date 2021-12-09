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
    # TODO(ralonsoh): remove 'target_tenant=*' reference.
    policy.RuleDefault(
        name='restrict_wildcard',
        check_str=base.policy_or(
            '(not field:rbac_policy:target_tenant=* and '
            'not field:rbac_policy:target_project=*)',
            base.RULE_ADMIN_ONLY),
        description='Definition of a wildcard target_project'),

    policy.DocumentedRuleDefault(
        name='create_rbac_policy',
        check_str=base.PROJECT_MEMBER,
        scope_types=['project'],
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
    # TODO(ralonsoh): change name to 'create_rbac_policy:target_project'
    # and remove 'target_tenant=*' reference.
    policy.DocumentedRuleDefault(
        name='create_rbac_policy:target_tenant',
        check_str=base.policy_or(
            base.PROJECT_ADMIN,
            '(not field:rbac_policy:target_tenant=* and '
            'not field:rbac_policy:target_project=*)'),
        description='Specify ``target_tenant`` when creating an RBAC policy',
        operations=[
            {
                'method': 'POST',
                'path': COLLECTION_PATH,
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='create_rbac_policy:target_tenant',
            check_str='rule:restrict_wildcard',
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_rbac_policy',
        check_str=base.PROJECT_MEMBER,
        scope_types=['project'],
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
    # TODO(ralonsoh): change name to 'create_rbac_policy:target_project'
    # and remove 'target_tenant=*' reference.
    policy.DocumentedRuleDefault(
        name='update_rbac_policy:target_tenant',
        check_str=base.policy_or(
            base.PROJECT_ADMIN,
            '(not field:rbac_policy:target_tenant=* and '
            'not field:rbac_policy:target_project=*)'),
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
        scope_types=['project'],
    ),
    policy.DocumentedRuleDefault(
        name='get_rbac_policy',
        check_str=base.PROJECT_READER,
        scope_types=['project'],
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
        check_str=base.PROJECT_MEMBER,
        scope_types=['project'],
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
