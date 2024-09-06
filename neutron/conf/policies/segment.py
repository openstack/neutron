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

DEPRECATED_REASON = (
    "The segment API now supports project scope and default roles.")

COLLECTION_PATH = '/segments'
RESOURCE_PATH = '/segments/{id}'
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
ACTION_POST_TAGS = [
    {'method': 'POST', 'path': TAGS_PATH},
]
ACTION_DELETE_TAGS = [
    {'method': 'DELETE', 'path': TAGS_PATH},
    {'method': 'DELETE', 'path': TAG_PATH},
]


rules = [
    policy.DocumentedRuleDefault(
        name='create_segment',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Create a segment',
        operations=[
            {
                'method': 'POST',
                'path': COLLECTION_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='create_segment',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_segments_tags',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Create the segment tags',
        operations=ACTION_POST_TAGS,
    ),
    policy.DocumentedRuleDefault(
        name='get_segment',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Get a segment',
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
        deprecated_rule=policy.DeprecatedRule(
            name='get_segment',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_segments_tags',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Get the segment tags',
        operations=ACTION_GET_TAGS,
    ),
    policy.DocumentedRuleDefault(
        name='update_segment',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Update a segment',
        operations=[
            {
                'method': 'PUT',
                'path': RESOURCE_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='update_segment',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_segments_tags',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Update the segment tags',
        operations=ACTION_PUT_TAGS,
    ),
    policy.DocumentedRuleDefault(
        name='delete_segment',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Delete a segment',
        operations=[
            {
                'method': 'DELETE',
                'path': RESOURCE_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_segment',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='delete_segments_tags',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Delete the segment tags',
        operations=ACTION_DELETE_TAGS,
    ),
]


def list_rules():
    return rules
