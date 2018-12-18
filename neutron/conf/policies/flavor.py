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
        'create_flavor',
        base.RULE_ADMIN_ONLY,
        description='Access rule for creating flavor'),
    policy.RuleDefault(
        'get_flavor',
        base.RULE_ANY,
        description='Access rule for getting flavor'),
    policy.RuleDefault(
        'update_flavor',
        base.RULE_ADMIN_ONLY,
        description='Access rule for updating flavor'),
    policy.RuleDefault(
        'delete_flavor',
        base.RULE_ADMIN_ONLY,
        description='Access rule for deleting flavor'),

    policy.RuleDefault(
        'create_service_profile',
        base.RULE_ADMIN_ONLY,
        description='Access rule for creating service profile'),
    policy.RuleDefault(
        'get_service_profile',
        base.RULE_ADMIN_ONLY,
        description='Access rule for getting service profile'),
    policy.RuleDefault(
        'update_service_profile',
        base.RULE_ADMIN_ONLY,
        description='Access rule for updating service profile'),
    policy.RuleDefault(
        'delete_service_profile',
        base.RULE_ADMIN_ONLY,
        description='Access rule for deleting service profile'),

    policy.RuleDefault(
        'create_flavor_service_profile',
        base.RULE_ADMIN_ONLY,
        description=('Access rule for associating '
                     'flavor with service profile')),
    policy.RuleDefault(
        'delete_flavor_service_profile',
        base.RULE_ADMIN_ONLY,
        description=('Access rule for disassociating '
                     'flavor with service profile')),
    policy.RuleDefault(
        'get_flavor_service_profile',
        base.RULE_ANY,
        description=('Access rule for getting flavor associating '
                     'with the given service profiles')),
]


def list_rules():
    return rules
