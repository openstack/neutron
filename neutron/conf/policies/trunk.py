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


COLLECTION_PATH = '/trunks'
RESOURCE_PATH = '/trunks/{id}'


rules = [
    policy.DocumentedRuleDefault(
        'create_trunk',
        base.RULE_ANY,
        'Create a trunk',
        [
            {
                'method': 'POST',
                'path': COLLECTION_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'get_trunk',
        base.RULE_ADMIN_OR_OWNER,
        'Get a trunk',
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
        'update_trunk',
        base.RULE_ADMIN_OR_OWNER,
        'Update a trunk',
        [
            {
                'method': 'PUT',
                'path': RESOURCE_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_trunk',
        base.RULE_ADMIN_OR_OWNER,
        'Delete a trunk',
        [
            {
                'method': 'DELETE',
                'path': RESOURCE_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'get_subports',
        base.RULE_ANY,
        'List subports attached to a trunk',
        [
            {
                'method': 'GET',
                'path': '/trunks/{id}/get_subports',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'add_subports',
        base.RULE_ADMIN_OR_OWNER,
        'Add subports to a trunk',
        [
            {
                'method': 'PUT',
                'path': '/trunks/{id}/add_subports',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'remove_subports',
        base.RULE_ADMIN_OR_OWNER,
        'Delete subports from a trunk',
        [
            {
                'method': 'PUT',
                'path': '/trunks/{id}/remove_subports',
            },
        ]
    ),
]


def list_rules():
    return rules
