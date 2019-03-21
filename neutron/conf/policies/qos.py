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


rules = [
    policy.DocumentedRuleDefault(
        'get_policy',
        base.RULE_ANY,
        'Get QoS policies',
        [
            {
                'method': 'GET',
                'path': '/qos/policies',
            },
            {
                'method': 'GET',
                'path': '/qos/policies/{id}',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'create_policy',
        base.RULE_ADMIN_ONLY,
        'Create a QoS policy',
        [
            {
                'method': 'POST',
                'path': '/qos/policies',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_policy',
        base.RULE_ADMIN_ONLY,
        'Update a QoS policy',
        [
            {
                'method': 'PUT',
                'path': '/qos/policies/{id}',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_policy',
        base.RULE_ADMIN_ONLY,
        'Delete a QoS policy',
        [
            {
                'method': 'DELETE',
                'path': '/qos/policies/{id}',
            },
        ]
    ),

    policy.DocumentedRuleDefault(
        'get_rule_type',
        base.RULE_ANY,
        'Get available QoS rule types',
        [
            {
                'method': 'GET',
                'path': '/qos/rule-types',
            },
            {
                'method': 'GET',
                'path': '/qos/rule-types/{rule_type}',
            },
        ]
    ),

    policy.DocumentedRuleDefault(
        'get_policy_bandwidth_limit_rule',
        base.RULE_ANY,
        'Get a QoS bandwidth limit rule',
        [
            {
                'method': 'GET',
                'path': '/qos/policies/{policy_id}/bandwidth_limit_rules',
            },
            {
                'method': 'GET',
                'path': ('/qos/policies/{policy_id}/'
                         'bandwidth_limit_rules/{rule_id}'),
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'create_policy_bandwidth_limit_rule',
        base.RULE_ADMIN_ONLY,
        'Create a QoS bandwidth limit rule',
        [
            {
                'method': 'POST',
                'path': '/qos/policies/{policy_id}/bandwidth_limit_rules',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_policy_bandwidth_limit_rule',
        base.RULE_ADMIN_ONLY,
        'Update a QoS bandwidth limit rule',
        [
            {
                'method': 'PUT',
                'path': ('/qos/policies/{policy_id}/'
                         'bandwidth_limit_rules/{rule_id}'),
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_policy_bandwidth_limit_rule',
        base.RULE_ADMIN_ONLY,
        'Delete a QoS bandwidth limit rule',
        [
            {
                'method': 'DELETE',
                'path': ('/qos/policies/{policy_id}/'
                         'bandwidth_limit_rules/{rule_id}'),
            },
        ]
    ),

    policy.DocumentedRuleDefault(
        'get_policy_dscp_marking_rule',
        base.RULE_ANY,
        'Get a QoS DSCP marking rule',
        [
            {
                'method': 'GET',
                'path': '/qos/policies/{policy_id}/dscp_marking_rules',
            },
            {
                'method': 'GET',
                'path': ('/qos/policies/{policy_id}/'
                         'dscp_marking_rules/{rule_id}'),
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'create_policy_dscp_marking_rule',
        base.RULE_ADMIN_ONLY,
        'Create a QoS DSCP marking rule',
        [
            {
                'method': 'POST',
                'path': '/qos/policies/{policy_id}/dscp_marking_rules',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_policy_dscp_marking_rule',
        base.RULE_ADMIN_ONLY,
        'Update a QoS DSCP marking rule',
        [
            {
                'method': 'PUT',
                'path': ('/qos/policies/{policy_id}/'
                         'dscp_marking_rules/{rule_id}'),
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_policy_dscp_marking_rule',
        base.RULE_ADMIN_ONLY,
        'Delete a QoS DSCP marking rule',
        [
            {
                'method': 'DELETE',
                'path': ('/qos/policies/{policy_id}/'
                         'dscp_marking_rules/{rule_id}'),
            },
        ]
    ),

    policy.DocumentedRuleDefault(
        'get_policy_minimum_bandwidth_rule',
        base.RULE_ANY,
        'Get a QoS minimum bandwidth rule',
        [
            {
                'method': 'GET',
                'path': '/qos/policies/{policy_id}/minimum_bandwidth_rules',
            },
            {
                'method': 'GET',
                'path': ('/qos/policies/{policy_id}/'
                         'minimum_bandwidth_rules/{rule_id}'),
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'create_policy_minimum_bandwidth_rule',
        base.RULE_ADMIN_ONLY,
        'Create a QoS minimum bandwidth rule',
        [
            {
                'method': 'POST',
                'path': '/qos/policies/{policy_id}/minimum_bandwidth_rules',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_policy_minimum_bandwidth_rule',
        base.RULE_ADMIN_ONLY,
        'Update a QoS minimum bandwidth rule',
        [
            {
                'method': 'PUT',
                'path': ('/qos/policies/{policy_id}/'
                         'minimum_bandwidth_rules/{rule_id}'),
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_policy_minimum_bandwidth_rule',
        base.RULE_ADMIN_ONLY,
        'Delete a QoS minimum bandwidth rule',
        [
            {
                'method': 'DELETE',
                'path': ('/qos/policies/{policy_id}/'
                         'minimum_bandwidth_rules/{rule_id}'),
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'get_alias_bandwidth_limit_rule',
        'rule:get_policy_bandwidth_limit_rule',
        'Get a QoS bandwidth limit rule through alias',
        [
            {
                'method': 'GET',
                'path': '/qos/alias_bandwidth_limit_rules/{rule_id}/',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_alias_bandwidth_limit_rule',
        'rule:update_policy_bandwidth_limit_rule',
        'Update a QoS bandwidth limit rule through alias',
        [
            {
                'method': 'PUT',
                'path': '/qos/alias_bandwidth_limit_rules/{rule_id}/',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_alias_bandwidth_limit_rule',
        'rule:delete_policy_bandwidth_limit_rule',
        'Delete a QoS bandwidth limit rule through alias',
        [
            {
                'method': 'DELETE',
                'path': '/qos/alias_bandwidth_limit_rules/{rule_id}/',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'get_alias_dscp_marking_rule',
        'rule:get_policy_dscp_marking_rule',
        'Get a QoS DSCP marking rule through alias',
        [
            {
                'method': 'GET',
                'path': '/qos/alias_dscp_marking_rules/{rule_id}/',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_alias_dscp_marking_rule',
        'rule:update_policy_dscp_marking_rule',
        'Update a QoS DSCP marking rule through alias',
        [
            {
                'method': 'PUT',
                'path': '/qos/alias_dscp_marking_rules/{rule_id}/',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_alias_dscp_marking_rule',
        'rule:delete_policy_dscp_marking_rule',
        'Delete a QoS DSCP marking rule through alias',
        [
            {
                'method': 'DELETE',
                'path': '/qos/alias_dscp_marking_rules/{rule_id}/',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'get_alias_minimum_bandwidth_rule',
        'rule:get_policy_minimum_bandwidth_rule',
        'Get a QoS minimum bandwidth rule through alias',
        [
            {
                'method': 'GET',
                'path': '/qos/alias_minimum_bandwidth_rules/{rule_id}/',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_alias_minimum_bandwidth_rule',
        'rule:update_policy_minimum_bandwidth_rule',
        'Update a QoS minimum bandwidth rule through alias',
        [
            {
                'method': 'PUT',
                'path': '/qos/alias_minimum_bandwidth_rules/{rule_id}/',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_alias_minimum_bandwidth_rule',
        'rule:delete_policy_minimum_bandwidth_rule',
        'Delete a QoS minimum bandwidth rule through alias',
        [
            {
                'method': 'DELETE',
                'path': '/qos/alias_minimum_bandwidth_rules/{rule_id}/',
            },
        ]
    ),
]


def list_rules():
    return rules
