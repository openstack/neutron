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
    policy.RuleDefault(
        'create_flavor',
        'rule:admin_only',
        description='Access rule for creating flavor'),
    policy.RuleDefault(
        'get_flavors',
        'rule:regular_user',
        description='Access rule for listing flavors'),
    policy.RuleDefault(
        'get_flavor',
        'rule:regular_user',
        description='Access rule for getting flavor'),
    policy.RuleDefault(
        'update_flavor',
        'rule:admin_only',
        description='Access rule for updating flavor'),
    policy.RuleDefault(
        'delete_flavor',
        'rule:admin_only',
        description='Access rule for deleting flavor'),

    policy.RuleDefault(
        'create_service_profile',
        'rule:admin_only',
        description='Access rule for creating service profile'),
    policy.RuleDefault(
        'get_service_profiles',
        'rule:admin_only',
        description='Access rule for listing service profiles'),
    policy.RuleDefault(
        'get_service_profile',
        'rule:admin_only',
        description='Access rule for getting service profile'),
    policy.RuleDefault(
        'update_service_profile',
        'rule:admin_only',
        description='Access rule for updating service profile'),
    policy.RuleDefault(
        'delete_service_profile',
        'rule:admin_only',
        description='Access rule for deleting service profile'),

    policy.RuleDefault(
        'create_flavor_service_profile',
        'rule:admin_only',
        description=('Access rule for associating '
                     'flavor with service profile')),
    policy.RuleDefault(
        'delete_flavor_service_profile',
        'rule:admin_only',
        description=('Access rule for disassociating '
                     'flavor with service profile')),
    policy.RuleDefault(
        'get_flavor_service_profile',
        'rule:regular_user',
        description=('Access rule for getting flavor associating '
                     'with the given service profiles')),
]


def list_rules():
    return rules
