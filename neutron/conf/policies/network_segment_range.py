# Copyright (c) 2019 Intel Corporation.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

from neutron_lib import policy as neutron_policy
from oslo_log import versionutils
from oslo_policy import policy

from neutron.conf.policies import base

DEPRECATED_REASON = """
The network segment range API now supports project scope and default roles.
"""

COLLECTION_PATH = '/network_segment_ranges'
RESOURCE_PATH = '/network_segment_ranges/{id}'
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


rules = [
    policy.DocumentedRuleDefault(
        name='create_network_segment_range',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Create a network segment range',
        operations=[
            {
                'method': 'POST',
                'path': COLLECTION_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='create_network_segment_range',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),

    policy.DocumentedRuleDefault(
        name='get_network_segment_range',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Get a network segment range',
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
            name='get_network_segment_range',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_network_segment_ranges_tags',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Get the network segment range tags',
        operations=ACTION_GET_TAGS,
    ),

    policy.DocumentedRuleDefault(
        name='update_network_segment_range',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Update a network segment range',
        operations=[
            {
                'method': 'PUT',
                'path': RESOURCE_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='update_network_segment_range',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_network_segment_ranges_tags',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Update the network segment range tags',
        operations=ACTION_PUT_TAGS,
    ),

    policy.DocumentedRuleDefault(
        name='delete_network_segment_range',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Delete a network segment range',
        operations=[
            {
                'method': 'DELETE',
                'path': RESOURCE_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_network_segment_range',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='delete_network_segment_ranges_tags',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Delete the network segment range tags',
        operations=ACTION_DELETE_TAGS,
    ),
]


def list_rules():
    return rules
