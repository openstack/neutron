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
from oslo_policy import policy

from neutron.conf.policies import base

DEPRECATED_REASON = (
    "The default security group rules API supports "
    "system scope and default roles.")


COLLECTION_PATH = '/default-security-group-rules'
RESOURCE_PATH = '/default-security-group-rules/{id}'


rules = [
    policy.DocumentedRuleDefault(
        name='create_default_security_group_rule',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Create a templated of the security group rule',
        operations=[
            {
                'method': 'POST',
                'path': COLLECTION_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='create_default_security_group_rule',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since='2023.2')
    ),
    policy.DocumentedRuleDefault(
        name='get_default_security_group_rule',
        # NOTE(slaweq): it can't be ADMIN_OR_PROJECT_READER constant from the
        # base module because that is using "project_id" in the check string
        # and this resource don't belongs to any project thus such
        # check string would fail enforcement.
        check_str='role:reader',
        scope_types=['project'],
        description='Get a templated of the security group rule',
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
            name='get_default_security_group_rule',
            check_str=neutron_policy.RULE_ANY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since='2023.2')
    ),
    policy.DocumentedRuleDefault(
        name='delete_default_security_group_rule',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Delete a templated of the security group rule',
        operations=[
            {
                'method': 'DELETE',
                'path': RESOURCE_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_default_security_group_rule',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since='2023.2')
    ),
]


def list_rules():
    return rules
