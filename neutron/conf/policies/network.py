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


COLLECTION_PATH = '/networks'
RESOURCE_PATH = '/networks/{id}'

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
    policy.RuleDefault(
        'external',
        'field:networks:router:external=True',
        'Definition of an external network'),

    policy.DocumentedRuleDefault(
        'create_network',
        base.RULE_ANY,
        'Create a network',
        ACTION_POST
    ),
    policy.DocumentedRuleDefault(
        'create_network:shared',
        base.RULE_ADMIN_ONLY,
        'Create a shared network',
        ACTION_POST
    ),
    policy.DocumentedRuleDefault(
        'create_network:router:external',
        base.RULE_ADMIN_ONLY,
        'Create an external network',
        ACTION_POST
    ),
    policy.DocumentedRuleDefault(
        'create_network:is_default',
        base.RULE_ADMIN_ONLY,
        'Specify ``is_default`` attribute when creating a network',
        ACTION_POST
    ),
    policy.DocumentedRuleDefault(
        'create_network:port_security_enabled',
        base.RULE_ANY,
        'Specify ``port_security_enabled`` attribute when creating a network',
        ACTION_POST
    ),
    policy.DocumentedRuleDefault(
        'create_network:segments',
        base.RULE_ADMIN_ONLY,
        'Specify ``segments`` attribute when creating a network',
        ACTION_POST
    ),
    policy.DocumentedRuleDefault(
        'create_network:provider:network_type',
        base.RULE_ADMIN_ONLY,
        'Specify ``provider:network_type`` when creating a network',
        ACTION_POST
    ),
    policy.DocumentedRuleDefault(
        'create_network:provider:physical_network',
        base.RULE_ADMIN_ONLY,
        'Specify ``provider:physical_network`` when creating a network',
        ACTION_POST
    ),
    policy.DocumentedRuleDefault(
        'create_network:provider:segmentation_id',
        base.RULE_ADMIN_ONLY,
        'Specify ``provider:segmentation_id`` when creating a network',
        ACTION_POST
    ),

    policy.DocumentedRuleDefault(
        'get_network',
        base.policy_or(base.RULE_ADMIN_OR_OWNER,
                       'rule:shared',
                       'rule:external',
                       base.RULE_ADVSVC),
        'Get a network',
        ACTION_GET
    ),
    policy.DocumentedRuleDefault(
        'get_network:router:external',
        base.RULE_ANY,
        'Get ``router:external`` attribute of a network',
        ACTION_GET
    ),
    policy.DocumentedRuleDefault(
        'get_network:segments',
        base.RULE_ADMIN_ONLY,
        'Get ``segments`` attribute of a network',
        ACTION_GET
    ),
    policy.DocumentedRuleDefault(
        'get_network:provider:network_type',
        base.RULE_ADMIN_ONLY,
        'Get ``provider:network_type`` attribute of a network',
        ACTION_GET
    ),
    policy.DocumentedRuleDefault(
        'get_network:provider:physical_network',
        base.RULE_ADMIN_ONLY,
        'Get ``provider:physical_network`` attribute of a network',
        ACTION_GET
    ),
    policy.DocumentedRuleDefault(
        'get_network:provider:segmentation_id',
        base.RULE_ADMIN_ONLY,
        'Get ``provider:segmentation_id`` attribute of a network',
        ACTION_GET
    ),

    policy.DocumentedRuleDefault(
        'update_network',
        base.RULE_ADMIN_OR_OWNER,
        'Update a network',
        ACTION_PUT
    ),
    policy.DocumentedRuleDefault(
        'update_network:segments',
        base.RULE_ADMIN_ONLY,
        'Update ``segments`` attribute of a network',
        ACTION_PUT
    ),
    policy.DocumentedRuleDefault(
        'update_network:shared',
        base.RULE_ADMIN_ONLY,
        'Update ``shared`` attribute of a network',
        ACTION_PUT
    ),
    policy.DocumentedRuleDefault(
        'update_network:provider:network_type',
        base.RULE_ADMIN_ONLY,
        'Update ``provider:network_type`` attribute of a network',
        ACTION_PUT
    ),
    policy.DocumentedRuleDefault(
        'update_network:provider:physical_network',
        base.RULE_ADMIN_ONLY,
        'Update ``provider:physical_network`` attribute of a network',
        ACTION_PUT
    ),
    policy.DocumentedRuleDefault(
        'update_network:provider:segmentation_id',
        base.RULE_ADMIN_ONLY,
        'Update ``provider:segmentation_id`` attribute of a network',
        ACTION_PUT
    ),
    policy.DocumentedRuleDefault(
        'update_network:router:external',
        base.RULE_ADMIN_ONLY,
        'Update ``router:external`` attribute of a network',
        ACTION_PUT
    ),
    policy.DocumentedRuleDefault(
        'update_network:is_default',
        base.RULE_ADMIN_ONLY,
        'Update ``is_default`` attribute of a network',
        ACTION_PUT
    ),
    policy.DocumentedRuleDefault(
        'update_network:port_security_enabled',
        base.RULE_ADMIN_OR_OWNER,
        'Update ``port_security_enabled`` attribute of a network',
        ACTION_PUT
    ),

    policy.DocumentedRuleDefault(
        'delete_network',
        base.RULE_ADMIN_OR_OWNER,
        'Delete a network',
        ACTION_DELETE
    ),
]


def list_rules():
    return rules
