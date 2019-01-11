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


LABEL_COLLECTION_PATH = '/metering/metering-labels'
LABEL_RESOURCE_PATH = '/metering/metering-labels/{id}'

RULE_COLLECTION_PATH = '/metering/metering-label-rules'
RULE_RESOURCE_PATH = '/metering/metering-label-rules/{id}'


rules = [
    policy.DocumentedRuleDefault(
        'create_metering_label',
        base.RULE_ADMIN_ONLY,
        'Create a metering label',
        [
            {
                'method': 'POST',
                'path': LABEL_COLLECTION_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'get_metering_label',
        base.RULE_ADMIN_ONLY,
        'Get a metering label',
        [
            {
                'method': 'GET',
                'path': LABEL_COLLECTION_PATH,
            },
            {
                'method': 'GET',
                'path': LABEL_RESOURCE_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_metering_label',
        base.RULE_ADMIN_ONLY,
        'Delete a metering label',
        [
            {
                'method': 'DELETE',
                'path': LABEL_RESOURCE_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'create_metering_label_rule',
        base.RULE_ADMIN_ONLY,
        'Create a metering label rule',
        [
            {
                'method': 'POST',
                'path': RULE_COLLECTION_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'get_metering_label_rule',
        base.RULE_ADMIN_ONLY,
        'Get a metering label rule',
        [
            {
                'method': 'GET',
                'path': RULE_COLLECTION_PATH,
            },
            {
                'method': 'GET',
                'path': RULE_RESOURCE_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_metering_label_rule',
        base.RULE_ADMIN_ONLY,
        'Delete a metering label rule',
        [
            {
                'method': 'DELETE',
                'path': RULE_RESOURCE_PATH,
            },
        ]
    )
]


def list_rules():
    return rules
