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


rules = [
    policy.RuleDefault('create_floatingip',
                       'rule:regular_user',
                       description='Access rule for creating floating IP'),
    policy.RuleDefault('create_floatingip:floating_ip_address',
                       'rule:admin_only',
                       description=('Access rule for creating floating IP '
                                    'with a specific IP address')),
    policy.RuleDefault('get_floatingip',
                       'rule:admin_or_owner',
                       description='Access rule for getting floating IP'),
    policy.RuleDefault('update_floatingip',
                       'rule:admin_or_owner',
                       description='Access rule for updating floating IP'),
    policy.RuleDefault('delete_floatingip',
                       'rule:admin_or_owner',
                       description='Access rule for deleting floating IP'),
]


def list_rules():
    return rules
