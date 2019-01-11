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


COLLECTION_PATH = '/subnets'
RESOURCE_PATH = '/subnets/{id}'

ACTION_POST = [
    {'method': 'POST', 'path': COLLECTION_PATH},
]
ACTION_PUT = [
    {'method': 'PUT', 'path': RESOURCE_PATH},
]
ACTION_DELETE = [
    {'method': 'DELETE', 'path': RESOURCE_PATH},
]
ACTION_GET = [
    {'method': 'GET', 'path': COLLECTION_PATH},
    {'method': 'GET', 'path': RESOURCE_PATH},
]


rules = [
    policy.DocumentedRuleDefault(
        'create_subnet',
        base.RULE_ADMIN_OR_NET_OWNER,
        'Create a subnet',
        ACTION_POST
    ),
    policy.DocumentedRuleDefault(
        'create_subnet:segment_id',
        base.RULE_ADMIN_ONLY,
        'Specify ``segment_id`` attribute when creating a subnet',
        ACTION_POST
    ),
    policy.DocumentedRuleDefault(
        'create_subnet:service_types',
        base.RULE_ADMIN_ONLY,
        'Specify ``service_types`` attribute when creating a subnet',
        ACTION_POST
    ),
    policy.DocumentedRuleDefault(
        'get_subnet',
        base.policy_or(base.RULE_ADMIN_OR_OWNER,
                       'rule:shared'),
        'Get a subnet',
        ACTION_GET
    ),
    policy.DocumentedRuleDefault(
        'get_subnet:segment_id',
        base.RULE_ADMIN_ONLY,
        'Get ``segment_id`` attribute of a subnet',
        ACTION_GET
    ),
    policy.DocumentedRuleDefault(
        'update_subnet',
        base.RULE_ADMIN_OR_NET_OWNER,
        'Update a subnet',
        ACTION_PUT
    ),
    policy.DocumentedRuleDefault(
        'update_subnet:segment_id',
        base.RULE_ADMIN_ONLY,
        'Update ``segment_id`` attribute of a subnet',
        ACTION_PUT
    ),
    policy.DocumentedRuleDefault(
        'update_subnet:service_types',
        base.RULE_ADMIN_ONLY,
        'Update ``service_types`` attribute of a subnet',
        ACTION_PUT
    ),
    policy.DocumentedRuleDefault(
        'delete_subnet',
        base.RULE_ADMIN_OR_NET_OWNER,
        'Delete a subnet',
        ACTION_DELETE,
    ),
]


def list_rules():
    return rules
