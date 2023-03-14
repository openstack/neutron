# Copyright 2021 Huawei, Inc.
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

COLLECTION_PATH = '/local-ips'
RESOURCE_PATH = '/local-ips/{id}'

DEPRECATION_REASON = (
    "The Local IP API now supports system scope and default roles.")

rules = [
    policy.DocumentedRuleDefault(
        name='create_local_ip',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        description='Create a Local IP',
        operations=[
            {
                'method': 'POST',
                'path': COLLECTION_PATH,
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='create_local_ip',
            check_str=neutron_policy.RULE_ANY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_local_ip',
        check_str=base.ADMIN_OR_PROJECT_READER,
        description='Get a Local IP',
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
            name='get_local_ip',
            check_str=neutron_policy.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_local_ip',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        description='Update a Local IP',
        operations=[
            {
                'method': 'PUT',
                'path': RESOURCE_PATH,
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='update_local_ip',
            check_str=neutron_policy.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='delete_local_ip',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        description='Delete a Local IP',
        operations=[
            {
                'method': 'DELETE',
                'path': RESOURCE_PATH,
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_local_ip',
            check_str=neutron_policy.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
]


def list_rules():
    return rules
