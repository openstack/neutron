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


SG_COLLECTION_PATH = '/security-groups'
SG_RESOURCE_PATH = '/security-groups/{id}'
RULE_COLLECTION_PATH = '/security-group-rules'
RULE_RESOURCE_PATH = '/security-group-rules/{id}'


rules = [
    # TODO(amotoki): admin_or_owner is the right rule?
    # Does an empty string make more sense for create_security_group?
    policy.DocumentedRuleDefault(
        'create_security_group',
        base.RULE_ADMIN_OR_OWNER,
        'Create a security group',
        [
            {
                'method': 'POST',
                'path': SG_COLLECTION_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'get_security_group',
        base.RULE_ANY,
        'Get a security group',
        [
            {
                'method': 'GET',
                'path': SG_COLLECTION_PATH,
            },
            {
                'method': 'GET',
                'path': SG_RESOURCE_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_security_group',
        base.RULE_ADMIN_OR_OWNER,
        'Update a security group',
        [
            {
                'method': 'PUT',
                'path': SG_RESOURCE_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_security_group',
        base.RULE_ADMIN_OR_OWNER,
        'Delete a security group',
        [
            {
                'method': 'DELETE',
                'path': SG_RESOURCE_PATH,
            },
        ]
    ),

    # TODO(amotoki): admin_or_owner is the right rule?
    # Does an empty string make more sense for create_security_group_rule?
    policy.DocumentedRuleDefault(
        'create_security_group_rule',
        base.RULE_ADMIN_OR_OWNER,
        'Create a security group rule',
        [
            {
                'method': 'POST',
                'path': RULE_COLLECTION_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'get_security_group_rule',
        base.RULE_ADMIN_OR_OWNER,
        'Get a security group rule',
        [
            {
                'method': 'GET',
                'path': RULE_COLLECTION_PATH,
            },
            {
                'method': 'GET',
                'path': RULE_RESOURCE_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_security_group_rule',
        base.RULE_ADMIN_OR_OWNER,
        'Delete a security group rule',
        [
            {
                'method': 'DELETE',
                'path': RULE_RESOURCE_PATH,
            },
        ]
    ),
]


def list_rules():
    return rules
