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

from neutron_lib import policy as neutron_policy
from oslo_log import versionutils
from oslo_policy import policy

from neutron.conf.policies import base


COLLECTION_PATH = '/floatingips'
RESOURCE_PATH = '/floatingips/{id}'
TAGS_PATH = RESOURCE_PATH + '/tags'
TAG_PATH = RESOURCE_PATH + '/tags/{tag_id}'

ACTION_GET_TAGS = [
    {'method': 'GET', 'path': TAGS_PATH},
    {'method': 'GET', 'path': TAG_PATH},
]
ACTION_PUT_TAGS = [
    {'method': 'PUT', 'path': TAGS_PATH},
    {'method': 'PUT', 'path': TAG_PATH},
]
ACTION_DELETE_TAGS = [
    {'method': 'DELETE', 'path': TAGS_PATH},
    {'method': 'DELETE', 'path': TAG_PATH},
]

DEPRECATION_REASON = (
    "The Floating IP API now supports system scope and default roles.")

rules = [
    policy.DocumentedRuleDefault(
        name='create_floatingip',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
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
            check_str=neutron_policy.RULE_ANY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_floatingip:floating_ip_address',
        check_str=base.ADMIN,
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
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_floatingip',
        check_str=base.ADMIN_OR_PROJECT_READER,
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
            check_str=neutron_policy.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_floatingips_tags',
        check_str=base.ADMIN_OR_PROJECT_READER,
        description='Get the floating IP tags',
        operations=ACTION_GET_TAGS,
        scope_types=['project'],
    ),

    policy.DocumentedRuleDefault(
        name='update_floatingip',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
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
            check_str=neutron_policy.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_floatingips_tags',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        description='Update the floating IP tags',
        operations=ACTION_PUT_TAGS,
        scope_types=['project'],
    ),

    policy.DocumentedRuleDefault(
        name='delete_floatingip',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
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
            check_str=neutron_policy.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='delete_floatingips_tags',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        description='Delete the floating IP tags',
        operations=ACTION_DELETE_TAGS,
        scope_types=['project'],
    ),
]


def list_rules():
    return rules
