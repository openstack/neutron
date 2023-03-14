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

DEPRECATED_REASON = """
The network API now supports system scope and default roles.
"""

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
        name='external',
        check_str='field:networks:router:external=True',
        description='Definition of an external network'),

    policy.DocumentedRuleDefault(
        name='create_network',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description='Create a network',
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_network',
            check_str=neutron_policy.RULE_ANY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_network:shared',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Create a shared network',
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_network:shared',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_network:router:external',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Create an external network',
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_network:router:external',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_network:is_default',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Specify ``is_default`` attribute when creating a network',
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_network:is_default',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_network:port_security_enabled',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description=(
            'Specify ``port_security_enabled`` '
            'attribute when creating a network'
        ),
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_network:port_security_enabled',
            check_str=neutron_policy.RULE_ANY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_network:segments',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Specify ``segments`` attribute when creating a network',
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_network:segments',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_network:provider:network_type',
        check_str=base.ADMIN,
        scope_types=['project'],
        description=(
            'Specify ``provider:network_type`` '
            'when creating a network'
        ),
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_network:provider:network_type',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_network:provider:physical_network',
        check_str=base.ADMIN,
        scope_types=['project'],
        description=(
            'Specify ``provider:physical_network`` '
            'when creating a network'
        ),
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_network:provider:physical_network',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_network:provider:segmentation_id',
        check_str=base.ADMIN,
        scope_types=['project'],
        description=(
            'Specify ``provider:segmentation_id`` when creating a network'
        ),
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_network:provider:segmentation_id',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),

    policy.DocumentedRuleDefault(
        name='get_network',
        check_str=neutron_policy.policy_or(
            base.ADMIN_OR_PROJECT_READER,
            'rule:shared',
            'rule:external',
            neutron_policy.RULE_ADVSVC
        ),
        scope_types=['project'],
        description='Get a network',
        operations=ACTION_GET,
        deprecated_rule=policy.DeprecatedRule(
            name='get_network',
            check_str=neutron_policy.policy_or(
                neutron_policy.RULE_ADMIN_OR_OWNER,
                'rule:shared',
                'rule:external',
                neutron_policy.RULE_ADVSVC),
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_network:segments',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Get ``segments`` attribute of a network',
        operations=ACTION_GET,
        deprecated_rule=policy.DeprecatedRule(
            name='get_network:segments',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_network:provider:network_type',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Get ``provider:network_type`` attribute of a network',
        operations=ACTION_GET,
        deprecated_rule=policy.DeprecatedRule(
            name='get_network:provider:network_type',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_network:provider:physical_network',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Get ``provider:physical_network`` attribute of a network',
        operations=ACTION_GET,
        deprecated_rule=policy.DeprecatedRule(
            name='get_network:provider:physical_network',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_network:provider:segmentation_id',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Get ``provider:segmentation_id`` attribute of a network',
        operations=ACTION_GET,
        deprecated_rule=policy.DeprecatedRule(
            name='get_network:provider:segmentation_id',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),

    policy.DocumentedRuleDefault(
        name='update_network',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description='Update a network',
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_network',
            check_str=neutron_policy.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_network:segments',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Update ``segments`` attribute of a network',
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_network:segments',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_network:shared',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Update ``shared`` attribute of a network',
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_network:shared',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_network:provider:network_type',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Update ``provider:network_type`` attribute of a network',
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_network:provider:network_type',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_network:provider:physical_network',
        check_str=base.ADMIN,
        scope_types=['project'],
        description=(
            'Update ``provider:physical_network`` '
            'attribute of a network'
        ),
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_network:provider:physical_network',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_network:provider:segmentation_id',
        check_str=base.ADMIN,
        scope_types=['project'],
        description=(
            'Update ``provider:segmentation_id`` '
            'attribute of a network'
        ),
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_network:provider:segmentation_id',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_network:router:external',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Update ``router:external`` attribute of a network',
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_network:router:external',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_network:is_default',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Update ``is_default`` attribute of a network',
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_network:is_default',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_network:port_security_enabled',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description='Update ``port_security_enabled`` attribute of a network',
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_network:port_security_enabled',
            check_str=neutron_policy.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),

    policy.DocumentedRuleDefault(
        name='delete_network',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description='Delete a network',
        operations=ACTION_DELETE,
        deprecated_rule=policy.DeprecatedRule(
            name='delete_network',
            check_str=neutron_policy.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
]


def list_rules():
    return rules
