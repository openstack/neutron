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
    policy.RuleDefault('get_policy',
                       base.RULE_ANY,
                       description='Access rule for getting QoS policy'),
    policy.RuleDefault('create_policy',
                       base.RULE_ADMIN_ONLY,
                       description='Access rule for creating QoS policy'),
    policy.RuleDefault('update_policy',
                       base.RULE_ADMIN_ONLY,
                       description='Access rule for updating QoS policy'),
    policy.RuleDefault('delete_policy',
                       base.RULE_ADMIN_ONLY,
                       description='Access rule for deleting QoS policy'),

    policy.RuleDefault('get_rule_type',
                       base.RULE_ANY,
                       description=('Access rule for getting '
                                    'all available QoS rule types')),

    policy.RuleDefault('get_policy_bandwidth_limit_rule',
                       base.RULE_ANY,
                       description=('Access rule for getting '
                                    'QoS bandwidth limit rule')),
    policy.RuleDefault('create_policy_bandwidth_limit_rule',
                       base.RULE_ADMIN_ONLY,
                       description=('Access rule for creating '
                                    'QoS bandwidth limit rule')),
    policy.RuleDefault('update_policy_bandwidth_limit_rule',
                       base.RULE_ADMIN_ONLY,
                       description=('Access rule for updating '
                                    'QoS bandwidth limit rule')),
    policy.RuleDefault('delete_policy_bandwidth_limit_rule',
                       base.RULE_ADMIN_ONLY,
                       description=('Access rule for deleting '
                                    'QoS bandwidth limit rule')),

    policy.RuleDefault('get_policy_dscp_marking_rule',
                       base.RULE_ANY,
                       description=('Access rule for getting '
                                    'QoS dscp marking rule')),
    policy.RuleDefault('create_policy_dscp_marking_rule',
                       base.RULE_ADMIN_ONLY,
                       description=('Access rule for creating '
                                    'QoS dscp marking rule')),
    policy.RuleDefault('update_policy_dscp_marking_rule',
                       base.RULE_ADMIN_ONLY,
                       description=('Access rule for updating '
                                    'QoS dscp marking rule')),
    policy.RuleDefault('delete_policy_dscp_marking_rule',
                       base.RULE_ADMIN_ONLY,
                       description=('Access rule for deleting '
                                    'QoS dscp marking rule')),

    policy.RuleDefault('get_policy_minimum_bandwidth_rule',
                       base.RULE_ANY,
                       description=('Access rule for getting '
                                   'QoS minimum bandwidth rule')),
    policy.RuleDefault('create_policy_minimum_bandwidth_rule',
                       base.RULE_ADMIN_ONLY,
                       description=('Access rule for creating '
                                    'QoS minimum bandwidth rule')),
    policy.RuleDefault('update_policy_minimum_bandwidth_rule',
                       base.RULE_ADMIN_ONLY,
                       description=('Access rule for updating '
                                    'QoS minimum bandwidth rule')),
    policy.RuleDefault('delete_policy_minimum_bandwidth_rule',
                       base.RULE_ADMIN_ONLY,
                       description=('Access rule for deleting '
                                    'QoS minimum bandwidth rule')),
]


def list_rules():
    return rules
