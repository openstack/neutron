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


AG_COLLECTION_PATH = '/address-groups'
AG_RESOURCE_PATH = '/address-groups/{id}'

DEPRECATION_REASON = (
    "The Address scope API now supports system scope and default roles.")


rules = [
    policy.RuleDefault(
        'shared_address_groups',
        'field:address_groups:shared=True',
        'Definition of a shared address group'
    ),
    policy.DocumentedRuleDefault(
        name='get_address_group',
        check_str=base.policy_or(
            base.SYSTEM_OR_PROJECT_READER,
            'rule:shared_address_groups'),
        description='Get an address group',
        operations=[
            {
                'method': 'GET',
                'path': AG_COLLECTION_PATH,
            },
            {
                'method': 'GET',
                'path': AG_RESOURCE_PATH,
            },
        ],
        scope_types=['system', 'project'],
        deprecated_rule=policy.DeprecatedRule(
            name='get_address_group',
            check_str=base.policy_or(base.RULE_ADMIN_OR_OWNER,
                                     'rule:shared_address_groups'),
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
]


def list_rules():
    return rules
