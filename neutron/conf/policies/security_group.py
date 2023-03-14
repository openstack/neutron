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

from neutron_lib import policy as neutron_policy
from oslo_log import versionutils
from oslo_policy import policy

from neutron.conf.policies import base

DEPRECATED_REASON = (
    "The security group API now supports system scope and default roles.")


SG_COLLECTION_PATH = '/security-groups'
SG_RESOURCE_PATH = '/security-groups/{id}'
RULE_COLLECTION_PATH = '/security-group-rules'
RULE_RESOURCE_PATH = '/security-group-rules/{id}'

RULE_ADMIN_OR_SG_OWNER = 'rule:admin_or_sg_owner'
RULE_ADMIN_OWNER_OR_SG_OWNER = 'rule:admin_owner_or_sg_owner'


rules = [
    policy.RuleDefault(
        name='admin_or_sg_owner',
        check_str=neutron_policy.policy_or(
            'rule:context_is_admin',
            'tenant_id:%(security_group:tenant_id)s'),
        description='Rule for admin or security group owner access'),
    policy.RuleDefault(
        name='admin_owner_or_sg_owner',
        check_str=neutron_policy.policy_or(
            'rule:owner',
            RULE_ADMIN_OR_SG_OWNER),
        description=('Rule for resource owner, '
                     'admin or security group owner access')),
    policy.RuleDefault(
        name='shared_security_group',
        check_str='field:security_groups:shared=True',
        description='Definition of a shared security group'
    ),
    # TODO(amotoki): admin_or_owner is the right rule?
    # Does an empty string make more sense for create_security_group?
    policy.DocumentedRuleDefault(
        name='create_security_group',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description='Create a security group',
        operations=[
            {
                'method': 'POST',
                'path': SG_COLLECTION_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='create_security_group',
            check_str=neutron_policy.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_security_group',
        check_str=neutron_policy.policy_or(
            base.ADMIN_OR_PROJECT_READER,
            'rule:shared_security_group'
        ),
        scope_types=['project'],
        description='Get a security group',
        operations=[
            {
                'method': 'GET',
                'path': SG_COLLECTION_PATH,
            },
            {
                'method': 'GET',
                'path': SG_RESOURCE_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='get_security_group',
            check_str=neutron_policy.RULE_ANY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_security_group',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description='Update a security group',
        operations=[
            {
                'method': 'PUT',
                'path': SG_RESOURCE_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='update_security_group',
            check_str=neutron_policy.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='delete_security_group',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description='Delete a security group',
        operations=[
            {
                'method': 'DELETE',
                'path': SG_RESOURCE_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_security_group',
            check_str=neutron_policy.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),

    # TODO(amotoki): admin_or_owner is the right rule?
    # Does an empty string make more sense for create_security_group_rule?
    policy.DocumentedRuleDefault(
        name='create_security_group_rule',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description='Create a security group rule',
        operations=[
            {
                'method': 'POST',
                'path': RULE_COLLECTION_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='create_security_group_rule',
            check_str=neutron_policy.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_security_group_rule',
        check_str=neutron_policy.policy_or(
            base.ADMIN_OR_PROJECT_READER,
            base.RULE_SG_OWNER),
        scope_types=['project'],
        description='Get a security group rule',
        operations=[
            {
                'method': 'GET',
                'path': RULE_COLLECTION_PATH,
            },
            {
                'method': 'GET',
                'path': RULE_RESOURCE_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='get_security_group_rule',
            check_str=RULE_ADMIN_OWNER_OR_SG_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='delete_security_group_rule',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description='Delete a security group rule',
        operations=[
            {
                'method': 'DELETE',
                'path': RULE_RESOURCE_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_security_group_rule',
            check_str=neutron_policy.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
]


def list_rules():
    return rules
