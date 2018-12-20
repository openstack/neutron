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
    policy.RuleDefault(
        'create_trunk',
        base.RULE_ANY,
        description='Access rule for creating trunk'),
    policy.RuleDefault(
        'get_trunk',
        base.RULE_ADMIN_OR_OWNER,
        description='Access rule for getting trunk'),
    policy.RuleDefault(
        'delete_trunk',
        base.RULE_ADMIN_OR_OWNER,
        description='Access rule for deleting trunk'),
    policy.RuleDefault(
        'get_subports',
        base.RULE_ANY,
        description='Access rule for listing subports attached to a trunk'),
    policy.RuleDefault(
        'add_subports',
        base.RULE_ADMIN_OR_OWNER,
        description='Access rule for adding subports to a trunk'),
    policy.RuleDefault(
        'remove_subports',
        base.RULE_ADMIN_OR_OWNER,
        description='Access rule for deleting subports from a trunk'),
]


def list_rules():
    return rules
