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

from oslo_log import versionutils
from oslo_policy import policy

from neutron.conf.policies import base

DEPRECATED_REASON = (
    "The router API now supports system scope and default roles.")

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
        name='create_router',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description='Create a router',
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_router',
            check_str=base.RULE_ANY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_router:distributed',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Specify ``distributed`` attribute when creating a router',
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_router:distributed',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_router:ha',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Specify ``ha`` attribute when creating a router',
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_router:ha',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_router:external_gateway_info',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description=('Specify ``external_gateway_info`` '
                     'information when creating a router'),
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_router:external_gateway_info',
            check_str=base.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_router:external_gateway_info:network_id',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description=('Specify ``network_id`` in ``external_gateway_info`` '
                     'information when creating a router'),
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_router:external_gateway_info:network_id',
            check_str=base.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_router:external_gateway_info:enable_snat',
        check_str=base.ADMIN,
        scope_types=['project'],
        description=('Specify ``enable_snat`` in ``external_gateway_info`` '
                     'information when creating a router'),
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_router:external_gateway_info:enable_snat',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_router:external_gateway_info:external_fixed_ips',
        check_str=base.ADMIN,
        scope_types=['project'],
        description=('Specify ``external_fixed_ips`` in '
                     '``external_gateway_info`` information when creating a '
                     'router'),
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_router:external_gateway_info:external_fixed_ips',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),

    policy.DocumentedRuleDefault(
        name='get_router',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description='Get a router',
        operations=ACTION_GET,
        deprecated_rule=policy.DeprecatedRule(
            name='get_router',
            check_str=base.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_router:distributed',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Get ``distributed`` attribute of a router',
        operations=ACTION_GET,
        deprecated_rule=policy.DeprecatedRule(
            name='get_router:distributed',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_router:ha',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Get ``ha`` attribute of a router',
        operations=ACTION_GET,
        deprecated_rule=policy.DeprecatedRule(
            name='get_router:ha',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),

    policy.DocumentedRuleDefault(
        name='update_router',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description='Update a router',
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_router',
            check_str=base.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_router:distributed',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Update ``distributed`` attribute of a router',
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_router:distributed',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_router:ha',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Update ``ha`` attribute of a router',
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_router:ha',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_router:external_gateway_info',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description='Update ``external_gateway_info`` information of a router',
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_router:external_gateway_info',
            check_str=base.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_router:external_gateway_info:network_id',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description=('Update ``network_id`` attribute of '
                     '``external_gateway_info`` information of a router'),
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_router:external_gateway_info:network_id',
            check_str=base.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_router:external_gateway_info:enable_snat',
        check_str=base.ADMIN,
        scope_types=['project'],
        description=('Update ``enable_snat`` attribute of '
                     '``external_gateway_info`` information of a router'),
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_router:external_gateway_info:enable_snat',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_router:external_gateway_info:external_fixed_ips',
        check_str=base.ADMIN,
        scope_types=['project'],
        description=('Update ``external_fixed_ips`` attribute of '
                     '``external_gateway_info`` information of a router'),
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_router:external_gateway_info:external_fixed_ips',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),

    policy.DocumentedRuleDefault(
        name='delete_router',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description='Delete a router',
        operations=ACTION_DELETE,
        deprecated_rule=policy.DeprecatedRule(
            name='delete_router',
            check_str=base.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),

    policy.DocumentedRuleDefault(
        name='add_router_interface',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description='Add an interface to a router',
        operations=[
            {
                'method': 'PUT',
                'path': '/routers/{id}/add_router_interface',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='add_router_interface',
            check_str=base.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='remove_router_interface',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description='Remove an interface from a router',
        operations=[
            {
                'method': 'PUT',
                'path': '/routers/{id}/remove_router_interface',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='remove_router_interface',
            check_str=base.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='add_extraroutes',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description='Add extra route to a router',
        operations=[
            {
                'method': 'PUT',
                'path': '/routers/{id}/add_extraroutes',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='add_extraroutes',
            check_str=base.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since="Xena")
    ),
    policy.DocumentedRuleDefault(
        name='remove_extraroutes',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description='Remove extra route from a router',
        operations=[
            {
                'method': 'PUT',
                'path': '/routers/{id}/remove_extraroutes',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='remove_extraroutes',
            check_str=base.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since="Xena")
    ),
]


def list_rules():
    return rules
