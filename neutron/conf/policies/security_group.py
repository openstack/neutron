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
    # TODO(amotoki): admin_or_owner is the right rule?
    # Does an empty string make more sense for create_security_group?
    policy.RuleDefault(
        'create_security_group',
        base.RULE_ADMIN_OR_OWNER,
        description='Access rule for creating security group'),
    policy.RuleDefault(
        'get_security_group',
        base.RULE_ADMIN_OR_OWNER,
        description='Access rule for getting security group'),
    policy.RuleDefault(
        'update_security_group',
        base.RULE_ADMIN_OR_OWNER,
        description='Access rule for updating security group'),
    policy.RuleDefault(
        'delete_security_group',
        base.RULE_ADMIN_OR_OWNER,
        description='Access rule for deleting security group'),

    # TODO(amotoki): admin_or_owner is the right rule?
    # Does an empty string make more sense for create_security_group_rule?
    policy.RuleDefault(
        'create_security_group_rule',
        base.RULE_ADMIN_OR_OWNER,
        description='Access rule for creating security group rule'),
    policy.RuleDefault(
        'get_security_group_rule',
        base.RULE_ADMIN_OR_OWNER,
        description='Access rule for getting security group rule'),
    policy.RuleDefault(
        'delete_security_group_rule',
        base.RULE_ADMIN_OR_OWNER,
        description='Access rule for deleting security group rule'),
]


def list_rules():
    return rules
