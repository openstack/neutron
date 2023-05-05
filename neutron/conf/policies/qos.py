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

DEPRECATED_REASON = """
The QoS API now supports project scope and default roles.
"""


rules = [
    policy.RuleDefault(
        'shared_qos_policy',
        'field:policies:shared=True',
        description='Rule of shared qos policy'),
    policy.DocumentedRuleDefault(
        name='get_policy',
        check_str=base.policy_or(
            base.ADMIN_OR_PROJECT_READER,
            'rule:shared_qos_policy'
        ),
        scope_types=['project'],
        description='Get QoS policies',
        operations=[
            {
                'method': 'GET',
                'path': '/qos/policies',
            },
            {
                'method': 'GET',
                'path': '/qos/policies/{id}',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='get_policy',
            check_str=base.RULE_ANY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_policy',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Create a QoS policy',
        operations=[
            {
                'method': 'POST',
                'path': '/qos/policies',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='create_policy',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_policy',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Update a QoS policy',
        operations=[
            {
                'method': 'PUT',
                'path': '/qos/policies/{id}',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='update_policy',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='delete_policy',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Delete a QoS policy',
        operations=[
            {
                'method': 'DELETE',
                'path': '/qos/policies/{id}',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_policy',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),

    policy.DocumentedRuleDefault(
        name='get_rule_type',
        # NOTE(ralonsoh): it can't be ADMIN_OR_PROJECT_READER constant from the
        # base module because that is using "project_id" in the check string
        # and the rule type resource don't belongs to any project thus such
        # check string would fail enforcement.
        check_str='role:reader',
        scope_types=['project'],
        description='Get available QoS rule types',
        operations=[
            {
                'method': 'GET',
                'path': '/qos/rule-types',
            },
            {
                'method': 'GET',
                'path': '/qos/rule-types/{rule_type}',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='get_rule_type',
            check_str=base.RULE_ANY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),

    policy.DocumentedRuleDefault(
        name='get_policy_bandwidth_limit_rule',
        check_str=base.ADMIN_OR_PARENT_OWNER_READER,
        scope_types=['project'],
        description='Get a QoS bandwidth limit rule',
        operations=[
            {
                'method': 'GET',
                'path': '/qos/policies/{policy_id}/bandwidth_limit_rules',
            },
            {
                'method': 'GET',
                'path': ('/qos/policies/{policy_id}/'
                         'bandwidth_limit_rules/{rule_id}'),
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='get_policy_bandwidth_limit_rule',
            check_str=base.RULE_ANY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_policy_bandwidth_limit_rule',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Create a QoS bandwidth limit rule',
        operations=[
            {
                'method': 'POST',
                'path': '/qos/policies/{policy_id}/bandwidth_limit_rules',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='create_policy_bandwidth_limit_rule',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_policy_bandwidth_limit_rule',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Update a QoS bandwidth limit rule',
        operations=[
            {
                'method': 'PUT',
                'path': ('/qos/policies/{policy_id}/'
                         'bandwidth_limit_rules/{rule_id}'),
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='update_policy_bandwidth_limit_rule',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='delete_policy_bandwidth_limit_rule',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Delete a QoS bandwidth limit rule',
        operations=[
            {
                'method': 'DELETE',
                'path': ('/qos/policies/{policy_id}/'
                         'bandwidth_limit_rules/{rule_id}'),
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_policy_bandwidth_limit_rule',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),

    policy.DocumentedRuleDefault(
        name='get_policy_packet_rate_limit_rule',
        check_str=base.ADMIN_OR_PARENT_OWNER_READER,
        scope_types=['project'],
        description='Get a QoS packet rate limit rule',
        operations=[
            {
                'method': 'GET',
                'path': '/qos/policies/{policy_id}/packet_rate_limit_rules',
            },
            {
                'method': 'GET',
                'path': ('/qos/policies/{policy_id}/'
                         'packet_rate_limit_rules/{rule_id}'),
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        name='create_policy_packet_rate_limit_rule',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Create a QoS packet rate limit rule',
        operations=[
            {
                'method': 'POST',
                'path': '/qos/policies/{policy_id}/packet_rate_limit_rules',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        name='update_policy_packet_rate_limit_rule',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Update a QoS packet rate limit rule',
        operations=[
            {
                'method': 'PUT',
                'path': ('/qos/policies/{policy_id}/'
                         'packet_rate_limit_rules/{rule_id}'),
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        name='delete_policy_packet_rate_limit_rule',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Delete a QoS packet rate limit rule',
        operations=[
            {
                'method': 'DELETE',
                'path': ('/qos/policies/{policy_id}/'
                         'packet_rate_limit_rules/{rule_id}'),
            },
        ]
    ),

    policy.DocumentedRuleDefault(
        name='get_policy_dscp_marking_rule',
        check_str=base.ADMIN_OR_PARENT_OWNER_READER,
        scope_types=['project'],
        description='Get a QoS DSCP marking rule',
        operations=[
            {
                'method': 'GET',
                'path': '/qos/policies/{policy_id}/dscp_marking_rules',
            },
            {
                'method': 'GET',
                'path': ('/qos/policies/{policy_id}/'
                         'dscp_marking_rules/{rule_id}'),
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='get_policy_dscp_marking_rule',
            check_str=base.RULE_ANY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_policy_dscp_marking_rule',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Create a QoS DSCP marking rule',
        operations=[
            {
                'method': 'POST',
                'path': '/qos/policies/{policy_id}/dscp_marking_rules',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='create_policy_dscp_marking_rule',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_policy_dscp_marking_rule',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Update a QoS DSCP marking rule',
        operations=[
            {
                'method': 'PUT',
                'path': ('/qos/policies/{policy_id}/'
                         'dscp_marking_rules/{rule_id}'),
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='update_policy_dscp_marking_rule',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='delete_policy_dscp_marking_rule',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Delete a QoS DSCP marking rule',
        operations=[
            {
                'method': 'DELETE',
                'path': ('/qos/policies/{policy_id}/'
                         'dscp_marking_rules/{rule_id}'),
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_policy_dscp_marking_rule',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),

    policy.DocumentedRuleDefault(
        name='get_policy_minimum_bandwidth_rule',
        check_str=base.ADMIN_OR_PARENT_OWNER_READER,
        scope_types=['project'],
        description='Get a QoS minimum bandwidth rule',
        operations=[
            {
                'method': 'GET',
                'path': '/qos/policies/{policy_id}/minimum_bandwidth_rules',
            },
            {
                'method': 'GET',
                'path': ('/qos/policies/{policy_id}/'
                         'minimum_bandwidth_rules/{rule_id}'),
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='get_policy_minimum_bandwidth_rule',
            check_str=base.RULE_ANY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_policy_minimum_bandwidth_rule',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Create a QoS minimum bandwidth rule',
        operations=[
            {
                'method': 'POST',
                'path': '/qos/policies/{policy_id}/minimum_bandwidth_rules',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='create_policy_minimum_bandwidth_rule',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_policy_minimum_bandwidth_rule',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Update a QoS minimum bandwidth rule',
        operations=[
            {
                'method': 'PUT',
                'path': ('/qos/policies/{policy_id}/'
                         'minimum_bandwidth_rules/{rule_id}'),
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='update_policy_minimum_bandwidth_rule',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='delete_policy_minimum_bandwidth_rule',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Delete a QoS minimum bandwidth rule',
        operations=[
            {
                'method': 'DELETE',
                'path': ('/qos/policies/{policy_id}/'
                         'minimum_bandwidth_rules/{rule_id}'),
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_policy_minimum_bandwidth_rule',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_policy_minimum_packet_rate_rule',
        check_str=base.ADMIN_OR_PARENT_OWNER_READER,
        scope_types=['project'],
        description='Get a QoS minimum packet rate rule',
        operations=[
            {
                'method': 'GET',
                'path': '/qos/policies/{policy_id}/minimum_packet_rate_rules',
            },
            {
                'method': 'GET',
                'path': ('/qos/policies/{policy_id}/'
                         'minimum_packet_rate_rules/{rule_id}'),
            },
        ],
    ),
    policy.DocumentedRuleDefault(
        name='create_policy_minimum_packet_rate_rule',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Create a QoS minimum packet rate rule',
        operations=[
            {
                'method': 'POST',
                'path': '/qos/policies/{policy_id}/minimum_packet_rate_rules',
            },
        ],
    ),
    policy.DocumentedRuleDefault(
        name='update_policy_minimum_packet_rate_rule',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Update a QoS minimum packet rate rule',
        operations=[
            {
                'method': 'PUT',
                'path': ('/qos/policies/{policy_id}/'
                         'minimum_packet_rate_rules/{rule_id}'),
            },
        ],
    ),
    policy.DocumentedRuleDefault(
        name='delete_policy_minimum_packet_rate_rule',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Delete a QoS minimum packet rate rule',
        operations=[
            {
                'method': 'DELETE',
                'path': ('/qos/policies/{policy_id}/'
                         'minimum_packet_rate_rules/{rule_id}'),
            },
        ],
    ),
    policy.DocumentedRuleDefault(
        name='get_alias_bandwidth_limit_rule',
        check_str=base.ADMIN_OR_PARENT_OWNER_READER,
        scope_types=['project'],
        description='Get a QoS bandwidth limit rule through alias',
        operations=[
            {
                'method': 'GET',
                'path': '/qos/alias_bandwidth_limit_rules/{rule_id}/',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='get_alias_bandwidth_limit_rule',
            check_str=base.RULE_ANY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_alias_bandwidth_limit_rule',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Update a QoS bandwidth limit rule through alias',
        operations=[
            {
                'method': 'PUT',
                'path': '/qos/alias_bandwidth_limit_rules/{rule_id}/',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='update_alias_bandwidth_limit_rule',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='delete_alias_bandwidth_limit_rule',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Delete a QoS bandwidth limit rule through alias',
        operations=[
            {
                'method': 'DELETE',
                'path': '/qos/alias_bandwidth_limit_rules/{rule_id}/',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_alias_bandwidth_limit_rule',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_alias_dscp_marking_rule',
        check_str=base.ADMIN_OR_PARENT_OWNER_READER,
        scope_types=['project'],
        description='Get a QoS DSCP marking rule through alias',
        operations=[
            {
                'method': 'GET',
                'path': '/qos/alias_dscp_marking_rules/{rule_id}/',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='get_alias_dscp_marking_rule',
            check_str=base.RULE_ANY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_alias_dscp_marking_rule',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Update a QoS DSCP marking rule through alias',
        operations=[
            {
                'method': 'PUT',
                'path': '/qos/alias_dscp_marking_rules/{rule_id}/',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='update_alias_dscp_marking_rule',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='delete_alias_dscp_marking_rule',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Delete a QoS DSCP marking rule through alias',
        operations=[
            {
                'method': 'DELETE',
                'path': '/qos/alias_dscp_marking_rules/{rule_id}/',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_alias_dscp_marking_rule',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_alias_minimum_bandwidth_rule',
        check_str=base.ADMIN_OR_PARENT_OWNER_READER,
        scope_types=['project'],
        description='Get a QoS minimum bandwidth rule through alias',
        operations=[
            {
                'method': 'GET',
                'path': '/qos/alias_minimum_bandwidth_rules/{rule_id}/',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='get_alias_minimum_bandwidth_rule',
            check_str=base.RULE_ANY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_alias_minimum_bandwidth_rule',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Update a QoS minimum bandwidth rule through alias',
        operations=[
            {
                'method': 'PUT',
                'path': '/qos/alias_minimum_bandwidth_rules/{rule_id}/',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='update_alias_minimum_bandwidth_rule',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='delete_alias_minimum_bandwidth_rule',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Delete a QoS minimum bandwidth rule through alias',
        operations=[
            {
                'method': 'DELETE',
                'path': '/qos/alias_minimum_bandwidth_rules/{rule_id}/',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_alias_minimum_bandwidth_rule',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_alias_minimum_packet_rate_rule',
        check_str='rule:get_policy_minimum_packet_rate_rule',
        scope_types=['project'],
        description='Get a QoS minimum packet rate rule through alias',
        operations=[
            {
                'method': 'GET',
                'path': '/qos/alias_minimum_packet_rate_rules/{rule_id}/',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        name='update_alias_minimum_packet_rate_rule',
        check_str='rule:update_policy_minimum_packet_rate_rule',
        scope_types=['project'],
        description='Update a QoS minimum packet rate rule through alias',
        operations=[
            {
                'method': 'PUT',
                'path': '/qos/alias_minimum_packet_rate_rules/{rule_id}/',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        name='delete_alias_minimum_packet_rate_rule',
        check_str='rule:delete_policy_minimum_packet_rate_rule',
        scope_types=['project'],
        description='Delete a QoS minimum packet rate rule through alias',
        operations=[
            {
                'method': 'DELETE',
                'path': '/qos/alias_minimum_packet_rate_rules/{rule_id}/',
            },
        ]
    ),
]


def list_rules():
    return rules
