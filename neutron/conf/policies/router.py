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


COLLECTION_PATH = '/routers'
RESOURCE_PATH = '/routers/{id}'

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
        'create_router',
        base.RULE_ANY,
        'Create a router',
        ACTION_POST
    ),
    policy.DocumentedRuleDefault(
        'create_router:distributed',
        base.RULE_ADMIN_ONLY,
        'Specify ``distributed`` attribute when creating a router',
        ACTION_POST
    ),
    policy.DocumentedRuleDefault(
        'create_router:ha',
        base.RULE_ADMIN_ONLY,
        'Specify ``ha`` attribute when creating a router',
        ACTION_POST
    ),
    policy.DocumentedRuleDefault(
        'create_router:external_gateway_info',
        base.RULE_ADMIN_OR_OWNER,
        'Specify ``external_gateway_info`` information when creating a router',
        ACTION_POST
    ),
    policy.DocumentedRuleDefault(
        'create_router:external_gateway_info:network_id',
        base.RULE_ADMIN_OR_OWNER,
        ('Specify ``network_id`` in ``external_gateway_info`` information '
         'when creating a router'),
        ACTION_POST
    ),
    policy.DocumentedRuleDefault(
        'create_router:external_gateway_info:enable_snat',
        base.RULE_ADMIN_ONLY,
        ('Specify ``enable_snat`` in ``external_gateway_info`` information '
         'when creating a router'),
        ACTION_POST
    ),
    policy.DocumentedRuleDefault(
        'create_router:external_gateway_info:external_fixed_ips',
        base.RULE_ADMIN_ONLY,
        ('Specify ``external_fixed_ips`` in ``external_gateway_info`` '
         'information when creating a router'),
        ACTION_POST
    ),

    policy.DocumentedRuleDefault(
        'get_router',
        base.RULE_ADMIN_OR_OWNER,
        'Get a router',
        ACTION_GET
    ),
    policy.DocumentedRuleDefault(
        'get_router:distributed',
        base.RULE_ADMIN_ONLY,
        'Get ``distributed`` attribute of a router',
        ACTION_GET
    ),
    policy.DocumentedRuleDefault(
        'get_router:ha',
        base.RULE_ADMIN_ONLY,
        'Get ``ha`` attribute of a router',
        ACTION_GET
    ),

    policy.DocumentedRuleDefault(
        'update_router',
        base.RULE_ADMIN_OR_OWNER,
        'Update a router',
        ACTION_PUT
    ),
    policy.DocumentedRuleDefault(
        'update_router:distributed',
        base.RULE_ADMIN_ONLY,
        'Update ``distributed`` attribute of a router',
        ACTION_PUT
    ),
    policy.DocumentedRuleDefault(
        'update_router:ha',
        base.RULE_ADMIN_ONLY,
        'Update ``ha`` attribute of a router',
        ACTION_PUT
    ),
    policy.DocumentedRuleDefault(
        'update_router:external_gateway_info',
        base.RULE_ADMIN_OR_OWNER,
        'Update ``external_gateway_info`` information of a router',
        ACTION_PUT
    ),
    policy.DocumentedRuleDefault(
        'update_router:external_gateway_info:network_id',
        base.RULE_ADMIN_OR_OWNER,
        ('Update ``network_id`` attribute of ``external_gateway_info`` '
         'information of a router'),
        ACTION_PUT
    ),
    policy.DocumentedRuleDefault(
        'update_router:external_gateway_info:enable_snat',
        base.RULE_ADMIN_ONLY,
        ('Update ``enable_snat`` attribute of ``external_gateway_info`` '
         'information of a router'),
        ACTION_PUT
    ),
    policy.DocumentedRuleDefault(
        'update_router:external_gateway_info:external_fixed_ips',
        base.RULE_ADMIN_ONLY,
        ('Update ``external_fixed_ips`` attribute of '
         '``external_gateway_info`` information of a router'),
        ACTION_PUT
    ),

    policy.DocumentedRuleDefault(
        'delete_router',
        base.RULE_ADMIN_OR_OWNER,
        'Delete a router',
        ACTION_DELETE
    ),

    policy.DocumentedRuleDefault(
        'add_router_interface',
        base.RULE_ADMIN_OR_OWNER,
        'Add an interface to a router',
        [
            {
                'method': 'PUT',
                'path': '/routers/{id}/add_router_interface',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'remove_router_interface',
        base.RULE_ADMIN_OR_OWNER,
        'Remove an interface from a router',
        [
            {
                'method': 'PUT',
                'path': '/routers/{id}/remove_router_interface',
            },
        ]
    ),
]


def list_rules():
    return rules
