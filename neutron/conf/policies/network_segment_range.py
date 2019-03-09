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

from oslo_policy import policy

from neutron.conf.policies import base


COLLECTION_PATH = '/network_segment_ranges'
RESOURCE_PATH = '/network_segment_ranges/{id}'


rules = [
    policy.DocumentedRuleDefault(
        'create_network_segment_range',
        base.RULE_ADMIN_ONLY,
        'Create a network segment range',
        [
            {
                'method': 'POST',
                'path': COLLECTION_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'get_network_segment_range',
        base.RULE_ADMIN_ONLY,
        'Get a network segment range',
        [
            {
                'method': 'GET',
                'path': COLLECTION_PATH,
            },
            {
                'method': 'GET',
                'path': RESOURCE_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_network_segment_range',
        base.RULE_ADMIN_ONLY,
        'Update a network segment range',
        [
            {
                'method': 'PUT',
                'path': RESOURCE_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_network_segment_range',
        base.RULE_ADMIN_ONLY,
        'Delete a network segment range',
        [
            {
                'method': 'DELETE',
                'path': RESOURCE_PATH,
            },
        ]
    ),
]


def list_rules():
    return rules
