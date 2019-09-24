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


COLLECTION_PATH = '/agents'
RESOURCE_PATH = '/agents/{id}'


rules = [
    policy.DocumentedRuleDefault(
        'get_agent',
        base.RULE_ADMIN_ONLY,
        'Get an agent',
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
        'update_agent',
        base.RULE_ADMIN_ONLY,
        'Update an agent',
        [
            {
                'method': 'PUT',
                'path': RESOURCE_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_agent',
        base.RULE_ADMIN_ONLY,
        'Delete an agent',
        [
            {
                'method': 'DELETE',
                'path': RESOURCE_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'create_dhcp-network',
        base.RULE_ADMIN_ONLY,
        'Add a network to a DHCP agent',
        [
            {
                'method': 'POST',
                'path': '/agents/{agent_id}/dhcp-networks',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'get_dhcp-networks',
        base.RULE_ADMIN_ONLY,
        'List networks on a DHCP agent',
        [
            {
                'method': 'GET',
                'path': '/agents/{agent_id}/dhcp-networks',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_dhcp-network',
        base.RULE_ADMIN_ONLY,
        'Remove a network from a DHCP agent',
        [
            {
                'method': 'DELETE',
                'path': '/agents/{agent_id}/dhcp-networks/{network_id}',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'create_l3-router',
        base.RULE_ADMIN_ONLY,
        'Add a router to an L3 agent',
        [
            {
                'method': 'POST',
                'path': '/agents/{agent_id}/l3-routers',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'get_l3-routers',
        base.RULE_ADMIN_ONLY,
        'List routers on an L3 agent',
        [
            {
                'method': 'GET',
                'path': '/agents/{agent_id}/l3-routers',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_l3-router',
        base.RULE_ADMIN_ONLY,
        'Remove a router from an L3 agent',
        [
            {
                'method': 'DELETE',
                'path': '/agents/{agent_id}/l3-routers/{router_id}',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'get_dhcp-agents',
        base.RULE_ADMIN_ONLY,
        'List DHCP agents hosting a network',
        [
            {
                'method': 'GET',
                'path': '/networks/{network_id}/dhcp-agents',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'get_l3-agents',
        base.RULE_ADMIN_ONLY,
        'List L3 agents hosting a router',
        [
            {
                'method': 'GET',
                'path': '/routers/{router_id}/l3-agents',
            },
        ]
    ),
]


def list_rules():
    return rules
