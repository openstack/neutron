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

from neutron_lib.policy import rules as lib_rules
from oslo_policy import policy


PORT_COLLECTION_PATH = '/ports'
PORT_RESOURCE_PATH = '/ports/{id}'

NETWORK_COLLECTION_PATH = '/networks'
NETWORK_RESOURCE_PATH = '/networks/{id}'

PORT_ACTION_POST: list[policy.Operation] = [
    {'method': 'POST', 'path': PORT_COLLECTION_PATH},
]
PORT_ACTION_PUT: list[policy.Operation] = [
    {'method': 'PUT', 'path': PORT_RESOURCE_PATH},
]
PORT_ACTION_GET: list[policy.Operation] = [
    {'method': 'GET', 'path': PORT_COLLECTION_PATH},
    {'method': 'GET', 'path': PORT_RESOURCE_PATH},
]

NETWORK_ACTION_POST: list[policy.Operation] = [
    {'method': 'POST', 'path': NETWORK_COLLECTION_PATH},
]
NETWORK_ACTION_PUT: list[policy.Operation] = [
    {'method': 'PUT', 'path': NETWORK_RESOURCE_PATH},
]
NETWORK_ACTION_GET: list[policy.Operation] = [
    {'method': 'GET', 'path': NETWORK_COLLECTION_PATH},
    {'method': 'GET', 'path': NETWORK_RESOURCE_PATH},
]

rules = [
    # Port PVLAN attributes
    policy.DocumentedRuleDefault(
        name='create_port:pvlan_type',
        check_str=lib_rules.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description='Specify ``pvlan_type`` attribute when creating a port',
        operations=PORT_ACTION_POST,
    ),
    policy.DocumentedRuleDefault(
        name='create_port:pvlan_community',
        check_str=lib_rules.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description=(
            'Specify ``pvlan_community`` attribute when creating a port'
        ),
        operations=PORT_ACTION_POST,
    ),
    policy.DocumentedRuleDefault(
        name='update_port:pvlan_type',
        check_str=lib_rules.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description='Update ``pvlan_type`` attribute of a port',
        operations=PORT_ACTION_PUT,
    ),
    policy.DocumentedRuleDefault(
        name='update_port:pvlan_community',
        check_str=lib_rules.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description='Update ``pvlan_community`` attribute of a port',
        operations=PORT_ACTION_PUT,
    ),
    policy.DocumentedRuleDefault(
        name='get_port:pvlan_type',
        check_str=lib_rules.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description='Get ``pvlan_type`` attribute of a port',
        operations=PORT_ACTION_GET,
    ),
    policy.DocumentedRuleDefault(
        name='get_port:pvlan_community',
        check_str=lib_rules.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description='Get ``pvlan_community`` attribute of a port',
        operations=PORT_ACTION_GET,
    ),

    # Network PVLAN attribute
    policy.DocumentedRuleDefault(
        name='create_network:pvlan',
        check_str=lib_rules.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description='Specify ``pvlan`` attribute when creating a network',
        operations=NETWORK_ACTION_POST,
    ),
    policy.DocumentedRuleDefault(
        name='update_network:pvlan',
        check_str=lib_rules.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description='Update ``pvlan`` attribute of a network',
        operations=NETWORK_ACTION_PUT,
    ),
    policy.DocumentedRuleDefault(
        name='get_network:pvlan',
        check_str=lib_rules.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description='Get ``pvlan`` attribute of a network',
        operations=NETWORK_ACTION_GET,
    ),
]


def list_rules():
    return rules
