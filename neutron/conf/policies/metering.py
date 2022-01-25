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

DEPRECATED_REASON = """
The metering API now supports system scope and default roles.
"""

LABEL_COLLECTION_PATH = '/metering/metering-labels'
LABEL_RESOURCE_PATH = '/metering/metering-labels/{id}'

RULE_COLLECTION_PATH = '/metering/metering-label-rules'
RULE_RESOURCE_PATH = '/metering/metering-label-rules/{id}'


rules = [
    policy.DocumentedRuleDefault(
        name='create_metering_label',
        check_str=base.PROJECT_ADMIN,
        scope_types=['project'],
        description='Create a metering label',
        operations=[
            {
                'method': 'POST',
                'path': LABEL_COLLECTION_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='create_metering_label',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_metering_label',
        check_str=base.PROJECT_READER,
        scope_types=['project'],
        description='Get a metering label',
        operations=[
            {
                'method': 'GET',
                'path': LABEL_COLLECTION_PATH,
            },
            {
                'method': 'GET',
                'path': LABEL_RESOURCE_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='get_metering_label',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='delete_metering_label',
        check_str=base.PROJECT_ADMIN,
        scope_types=['project'],
        description='Delete a metering label',
        operations=[
            {
                'method': 'DELETE',
                'path': LABEL_RESOURCE_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_metering_label',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_metering_label_rule',
        check_str=base.PROJECT_ADMIN,
        scope_types=['project'],
        description='Create a metering label rule',
        operations=[
            {
                'method': 'POST',
                'path': RULE_COLLECTION_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='create_metering_label_rule',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_metering_label_rule',
        check_str=base.PROJECT_READER,
        scope_types=['project'],
        description='Get a metering label rule',
        operations=[
            {
                'method': 'GET',
                'path': RULE_COLLECTION_PATH,
            },
            {
                'method': 'GET',
                'path': RULE_RESOURCE_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='get_metering_label_rule',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='delete_metering_label_rule',
        check_str=base.PROJECT_ADMIN,
        scope_types=['project'],
        description='Delete a metering label rule',
        operations=[
            {
                'method': 'DELETE',
                'path': RULE_RESOURCE_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_metering_label_rule',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    )
]


def list_rules():
    return rules
