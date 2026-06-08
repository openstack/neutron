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


COLLECTION_PATH = '/routers'
RESOURCE_PATH = '/routers/{id}'

ACTION_POST: list[policy.Operation] = [
    {'method': 'POST', 'path': COLLECTION_PATH},
]
ACTION_GET: list[policy.Operation] = [
    {'method': 'GET', 'path': COLLECTION_PATH},
    {'method': 'GET', 'path': RESOURCE_PATH},
]

rules = [
    policy.DocumentedRuleDefault(
        name='create_router:evpn_vni',
        check_str=lib_rules.ADMIN,
        scope_types=['project'],
        description='Specify ``evpn_vni`` attribute when creating a router',
        operations=ACTION_POST,
    ),
    policy.DocumentedRuleDefault(
        name='get_router:evpn_vni',
        check_str=lib_rules.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description='Get ``evpn_vni`` attribute of a router',
        operations=ACTION_GET,
    ),
]


def list_rules():
    return rules
