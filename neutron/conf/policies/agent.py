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

from neutron_lib import policy as neutron_policy
from oslo_log import versionutils
from oslo_policy import policy

from neutron.conf.policies import base


COLLECTION_PATH = '/agents'
RESOURCE_PATH = '/agents/{id}'

DEPRECATION_REASON = (
    "The Agent API now supports project scope and default roles.")

rules = [
    policy.DocumentedRuleDefault(
        name='create_agent',
        check_str=base.ADMIN,
        description='Create an agent',
        operations=[
            {
                'method': 'POST',
                'path': RESOURCE_PATH,
            },
        ],
        scope_types=['project'],
    ),
    policy.DocumentedRuleDefault(
        name='get_agent',
        check_str=base.ADMIN,
        description='Get an agent',
        operations=[
            {
                'method': 'GET',
                'path': COLLECTION_PATH,
            },
            {
                'method': 'GET',
                'path': RESOURCE_PATH,
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='get_agent',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_agent',
        check_str=base.ADMIN,
        description='Update an agent',
        operations=[
            {
                'method': 'PUT',
                'path': RESOURCE_PATH,
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='update_agent',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='delete_agent',
        check_str=base.ADMIN,
        description='Delete an agent',
        operations=[
            {
                'method': 'DELETE',
                'path': RESOURCE_PATH,
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_agent',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_dhcp-network',
        check_str=base.ADMIN,
        description='Add a network to a DHCP agent',
        operations=[
            {
                'method': 'POST',
                'path': '/agents/{agent_id}/dhcp-networks',
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='create_dhcp-network',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_dhcp-networks',
        check_str=base.ADMIN,
        description='List networks on a DHCP agent',
        operations=[
            {
                'method': 'GET',
                'path': '/agents/{agent_id}/dhcp-networks',
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='get_dhcp-networks',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='delete_dhcp-network',
        check_str=base.ADMIN,
        description='Remove a network from a DHCP agent',
        operations=[
            {
                'method': 'DELETE',
                'path': '/agents/{agent_id}/dhcp-networks/{network_id}',
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_dhcp-network',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_l3-router',
        check_str=base.ADMIN,
        description='Add a router to an L3 agent',
        operations=[
            {
                'method': 'POST',
                'path': '/agents/{agent_id}/l3-routers',
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='create_l3-router',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_l3-routers',
        check_str=base.ADMIN,
        description='List routers on an L3 agent',
        operations=[
            {
                'method': 'GET',
                'path': '/agents/{agent_id}/l3-routers',
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='get_l3-routers',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='delete_l3-router',
        check_str=base.ADMIN,
        description='Remove a router from an L3 agent',
        operations=[
            {
                'method': 'DELETE',
                'path': '/agents/{agent_id}/l3-routers/{router_id}',
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_l3-router',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_dhcp-agents',
        check_str=base.ADMIN,
        description='List DHCP agents hosting a network',
        operations=[
            {
                'method': 'GET',
                'path': '/networks/{network_id}/dhcp-agents',
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='get_dhcp-agents',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_l3-agents',
        check_str=base.ADMIN,
        description='List L3 agents hosting a router',
        operations=[
            {
                'method': 'GET',
                'path': '/routers/{router_id}/l3-agents',
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='get_l3-agents',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
]


def list_rules():
    return rules
