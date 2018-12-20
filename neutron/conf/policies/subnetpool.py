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
    policy.RuleDefault('shared_subnetpools',
                       'field:subnetpools:shared=True',
                       description='Rule of shared subnetpool'),
    policy.RuleDefault('create_subnetpool',
                       base.RULE_ANY,
                       description='Access rule for creating subnetpool'),
    policy.RuleDefault('create_subnetpool:shared',
                       base.RULE_ADMIN_ONLY,
                       description=('Access rule for creating '
                                    'shared subnetpool')),
    policy.RuleDefault('create_subnetpool:is_default',
                       base.RULE_ADMIN_ONLY,
                       description=('Access rule for creating '
                                    'subnetpool with is_default')),
    policy.RuleDefault('get_subnetpool',
                       base.policy_or(base.RULE_ADMIN_OR_OWNER,
                                      'rule:shared_subnetpools'),
                       description='Access rule for getting subnetpool'),
    policy.RuleDefault('update_subnetpool',
                       base.RULE_ADMIN_OR_OWNER,
                       description='Access rule for updating subnetpool'),
    policy.RuleDefault('update_subnetpool:is_default',
                       base.RULE_ADMIN_ONLY,
                       description=('Access rule for updating '
                                    'is_default of subnetpool')),
    policy.RuleDefault('delete_subnetpool',
                       base.RULE_ADMIN_OR_OWNER,
                       description='Access rule for deleting subnetpool')
]


def list_rules():
    return rules
