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


COLLECTION_PATH = '/floatingips'
RESOURCE_PATH = '/floatingips/{id}'

DEPRECATION_REASON = (
    "The Floating IP API now supports system scope and default roles.")

rules = [
    policy.DocumentedRuleDefault(
        name='create_floatingip',
        check_str=base.PROJECT_MEMBER,
        description='Create a floating IP',
        operations=[
            {
                'method': 'POST',
                'path': COLLECTION_PATH,
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='create_floatingip',
            check_str=base.RULE_ANY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_floatingip:floating_ip_address',
        check_str=base.PROJECT_ADMIN,
        description='Create a floating IP with a specific IP address',
        operations=[
            {
                'method': 'POST',
                'path': COLLECTION_PATH,
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='create_floatingip:floating_ip_address',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_floatingip',
        check_str=base.PROJECT_READER,
        description='Get a floating IP',
        operations=[
            {
                'method': 'GET',
                'path': COLLECTION_PATH,
            },
            {
                'method': 'GET',
                'path': RESOURCE_PATH,
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='get_floatingip',
            check_str=base.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_floatingip',
        check_str=base.PROJECT_MEMBER,
        description='Update a floating IP',
        operations=[
            {
                'method': 'PUT',
                'path': RESOURCE_PATH,
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='update_floatingip',
            check_str=base.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='delete_floatingip',
        check_str=base.PROJECT_MEMBER,
        description='Delete a floating IP',
        operations=[
            {
                'method': 'DELETE',
                'path': RESOURCE_PATH,
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_floatingip',
            check_str=base.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
]


def list_rules():
    return rules
