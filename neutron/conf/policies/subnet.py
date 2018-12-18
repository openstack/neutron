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
    policy.RuleDefault('create_subnet',
                       base.RULE_ADMIN_OR_NET_OWNER,
                       description='Access rule for creating subnet'),
    policy.RuleDefault('create_subnet:segment_id',
                       base.RULE_ADMIN_ONLY,
                       description=('Access rule for creating '
                                    'subnet with segment_id')),
    policy.RuleDefault('create_subnet:service_types',
                       base.RULE_ADMIN_ONLY,
                       description=('Access rule for creating '
                                    'subnet with service_type')),
    policy.RuleDefault('get_subnet',
                       base.policy_or(base.RULE_ADMIN_OR_OWNER,
                                      'rule:shared'),
                       description='Access rule for getting subnet'),
    policy.RuleDefault('get_subnet:segment_id',
                       base.RULE_ADMIN_ONLY,
                       description=('Access rule for getting '
                                    'segment_id of subnet')),
    policy.RuleDefault('update_subnet',
                       base.RULE_ADMIN_OR_NET_OWNER,
                       description='Access rule for updating subnet'),
    policy.RuleDefault('update_subnet:service_types',
                       base.RULE_ADMIN_ONLY,
                       description=('Access rule for updating '
                                    'service_types of subnet')),
    policy.RuleDefault('delete_subnet',
                       base.RULE_ADMIN_OR_NET_OWNER,
                       description='Access rule for deleting subnet')
]


def list_rules():
    return rules
