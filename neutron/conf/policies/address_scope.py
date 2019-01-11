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


COLLECTION_PATH = '/address-scopes'
RESOURCE_PATH = '/address-scopes/{id}'


rules = [
    policy.RuleDefault(
        'shared_address_scopes',
        'field:address_scopes:shared=True',
        'Definition of a shared address scope'
    ),
    policy.DocumentedRuleDefault(
        'create_address_scope',
        base.RULE_ANY,
        'Create an address scope',
        [
            {
                'method': 'POST',
                'path': COLLECTION_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'create_address_scope:shared',
        base.RULE_ADMIN_ONLY,
        'Create a shared address scope',
        [
            {
                'method': 'POST',
                'path': COLLECTION_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'get_address_scope',
        base.policy_or(base.RULE_ADMIN_OR_OWNER,
                       'rule:shared_address_scopes'),
        'Get an address scope',
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
        'update_address_scope',
        base.RULE_ADMIN_OR_OWNER,
        'Update an address scope',
        [
            {
                'method': 'PUT',
                'path': RESOURCE_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_address_scope:shared',
        base.RULE_ADMIN_ONLY,
        'Update ``shared`` attribute of an address scope',
        [
            {
                'method': 'PUT',
                'path': RESOURCE_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_address_scope',
        base.RULE_ADMIN_OR_OWNER,
        'Delete an address scope',
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
