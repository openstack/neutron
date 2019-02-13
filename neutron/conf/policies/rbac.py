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


COLLECTION_PATH = '/rbac-policies'
RESOURCE_PATH = '/rbac-policies/{id}'


rules = [
    policy.RuleDefault(
        'restrict_wildcard',
        base.policy_or('(not field:rbac_policy:target_tenant=*)',
                       base.RULE_ADMIN_ONLY),
        'Definition of a wildcard target_tenant'),

    policy.DocumentedRuleDefault(
        'create_rbac_policy',
        base.RULE_ANY,
        'Create an RBAC policy',
        [
            {
                'method': 'POST',
                'path': COLLECTION_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'create_rbac_policy:target_tenant',
        'rule:restrict_wildcard',
        'Specify ``target_tenant`` when creating an RBAC policy',
        [
            {
                'method': 'POST',
                'path': COLLECTION_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_rbac_policy',
        base.RULE_ADMIN_OR_OWNER,
        'Update an RBAC policy',
        [
            {
                'method': 'PUT',
                'path': RESOURCE_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_rbac_policy:target_tenant',
        base.policy_and('rule:restrict_wildcard',
                        base.RULE_ADMIN_OR_OWNER),
        'Update ``target_tenant`` attribute of an RBAC policy',
        [
            {
                'method': 'PUT',
                'path': RESOURCE_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'get_rbac_policy',
        base.RULE_ADMIN_OR_OWNER,
        'Get an RBAC policy',
        [
            {
                'method': 'GET',
                'path': COLLECTION_PATH,
            },
            {
                'method': 'GET',
                'path': RESOURCE_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_rbac_policy',
        base.RULE_ADMIN_OR_OWNER,
        'Delete an RBAC policy',
        [
            {
                'method': 'DELETE',
                'path': RESOURCE_PATH,
            },
        ]
    ),
]


def list_rules():
    return rules
