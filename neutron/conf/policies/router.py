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


rules = [
    policy.RuleDefault(
        'create_router',
        'rule:regular_user',
        description='Access rule for creating router'),
    policy.RuleDefault(
        'create_router:distributed',
        'rule:admin_only',
        description=('Access rule for creating '
                     'router with distributed attribute')),
    policy.RuleDefault(
        'create_router:ha',
        'rule:admin_only',
        description=('Access rule for creating '
                     'router with ha attribute')),
    policy.RuleDefault(
        'create_router:external_gateway_info',
        'rule:admin_or_owner',
        description=('Access rule for creating router with '
                     'external_gateway_info information')),
    policy.RuleDefault(
        'create_router:external_gateway_info:network_id',
        'rule:admin_or_owner',
        description=('Access rule for creating router with network_id '
                     'attribute of external_gateway_info information')),
    policy.RuleDefault(
        'create_router:external_gateway_info:enable_snat',
        'rule:admin_only',
        description=('Access rule for creating router with enable_snat '
                     'attribute of external_gateway_info information')),
    policy.RuleDefault(
        'create_router:external_gateway_info:external_fixed_ips',
        'rule:admin_only',
        description=('Access rule for creating router with '
                     'external_fixed_ips attribute of '
                     'external_gateway_info information')),

    policy.RuleDefault(
        'get_router',
        'rule:admin_or_owner',
        description='Access rule for getting router'),
    policy.RuleDefault(
        'get_router:distributed',
        'rule:admin_only',
        description=('Access rule for getting distributed attribute of '
                     'router')),
    policy.RuleDefault(
        'get_router:ha',
        'rule:admin_only',
        description='Access rule for getting ha attribute of router'),

    policy.RuleDefault(
        'update_router',
        'rule:admin_or_owner',
        description='Access rule for updating router'),
    policy.RuleDefault(
        'update_router:distributed',
        'rule:admin_only',
        description=('Access rule for updating distributed attribute '
                     'of router')),
    policy.RuleDefault(
        'update_router:ha',
        'rule:admin_only',
        description='Access rule for updating ha attribute of router'),
    policy.RuleDefault(
        'update_router:external_gateway_info',
        'rule:admin_or_owner',
        description=('Access rule for updating external_gateway_info '
                     'information of router')),
    policy.RuleDefault(
        'update_router:external_gateway_info:network_id',
        'rule:admin_or_owner',
        description=('Access rule for updating network_id attribute of '
                     'external_gateway_info information of router')),
    policy.RuleDefault(
        'update_router:external_gateway_info:enable_snat',
        'rule:admin_only',
        description=('Access rule for updating enable_snat attribute of '
                     'external_gateway_info information of router')),
    policy.RuleDefault(
        'update_router:external_gateway_info:external_fixed_ips',
        'rule:admin_only',
        description=('Access rule for updating external_fixed_ips '
                     'attribute of external_gateway_info information '
                     'of router')),

    policy.RuleDefault(
        'delete_router',
        'rule:admin_or_owner',
        description='Access rule for deleting router'),

    policy.RuleDefault(
        'add_router_interface',
        'rule:admin_or_owner',
        description='Access rule for adding router interface'),
    policy.RuleDefault(
        'remove_router_interface',
        'rule:admin_or_owner',
        description='Access rule for removing router interface'),
]


def list_rules():
    return rules
