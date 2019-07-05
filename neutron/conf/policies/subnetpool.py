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


COLLECTION_PATH = '/subnetpools'
RESOURCE_PATH = '/subnetpools/{id}'
ONBOARD_PATH = '/subnetpools/{id}/onboard_network_subnets'
ADD_PREFIXES_PATH = '/subnetpools/{id}/add_prefixes'
REMOVE_PREFIXES_PATH = '/subnetpools/{id}/remove_prefixes'


rules = [
    policy.RuleDefault(
        'shared_subnetpools',
        'field:subnetpools:shared=True',
        'Definition of a shared subnetpool'
    ),
    policy.DocumentedRuleDefault(
        'create_subnetpool',
        base.RULE_ANY,
        'Create a subnetpool',
        [
            {
                'method': 'POST',
                'path': COLLECTION_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'create_subnetpool:shared',
        base.RULE_ADMIN_ONLY,
        'Create a shared subnetpool',
        [
            {
                'method': 'POST',
                'path': COLLECTION_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'create_subnetpool:is_default',
        base.RULE_ADMIN_ONLY,
        'Specify ``is_default`` attribute when creating a subnetpool',
        [
            {
                'method': 'POST',
                'path': COLLECTION_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'get_subnetpool',
        base.policy_or(base.RULE_ADMIN_OR_OWNER,
                       'rule:shared_subnetpools'),
        'Get a subnetpool',
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
        'update_subnetpool',
        base.RULE_ADMIN_OR_OWNER,
        'Update a subnetpool',
        [
            {
                'method': 'PUT',
                'path': RESOURCE_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_subnetpool:is_default',
        base.RULE_ADMIN_ONLY,
        'Update ``is_default`` attribute of a subnetpool',
        [
            {
                'method': 'PUT',
                'path': RESOURCE_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_subnetpool',
        base.RULE_ADMIN_OR_OWNER,
        'Delete a subnetpool',
        [
            {
                'method': 'DELETE',
                'path': RESOURCE_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'onboard_network_subnets',
        base.RULE_ADMIN_OR_OWNER,
        'Onboard existing subnet into a subnetpool',
        [
            {
                'method': 'Put',
                'path': ONBOARD_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'add_prefixes',
        base.RULE_ADMIN_OR_OWNER,
        'Add prefixes to a subnetpool',
        [
            {
                'method': 'Put',
                'path': ADD_PREFIXES_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'remove_prefixes',
        base.RULE_ADMIN_OR_OWNER,
        'Remove unallocated prefixes from a subnetpool',
        [
            {
                'method': 'Put',
                'path': REMOVE_PREFIXES_PATH,
            },
        ]
    ),
]


def list_rules():
    return rules
