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

from oslo_policy import policy

from neutron.conf.policies import base


rules = [
    policy.RuleDefault(
        'restrict_wildcard',
        base.policy_or('(not field:rbac_policy:target_tenant=*)',
                       base.RULE_ADMIN_ONLY),
        description='Rule of restrict wildcard'),

    policy.RuleDefault(
        'create_rbac_policy',
        base.RULE_ANY,
        description='Access rule for creating RBAC policy'),
    policy.RuleDefault(
        'create_rbac_policy:target_tenant',
        'rule:restrict_wildcard',
        description=('Access rule for creating RBAC '
                     'policy with a specific target tenant')),
    policy.RuleDefault(
        'update_rbac_policy',
        base.RULE_ADMIN_OR_OWNER,
        description='Access rule for updating RBAC policy'),
    policy.RuleDefault(
        'update_rbac_policy:target_tenant',
        base.policy_and('rule:restrict_wildcard',
                        base.RULE_ADMIN_OR_OWNER),
        description=('Access rule for updating target_tenant '
                     'attribute of RBAC policy')),
    policy.RuleDefault(
        'get_rbac_policy',
        base.RULE_ADMIN_OR_OWNER,
        description='Access rule for getting RBAC policy'),
    policy.RuleDefault(
        'delete_rbac_policy',
        base.RULE_ADMIN_OR_OWNER,
        description='Access rule for deleting RBAC policy'),
]


def list_rules():
    return rules
