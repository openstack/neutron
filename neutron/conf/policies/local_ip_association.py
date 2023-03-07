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

COLLECTION_PATH = '/local_ips/{local_ip_id}/port_associations'
RESOURCE_PATH = ('/local_ips/{local_ip_id}'
                 '/port_associations/{fixed_port_id}')

DEPRECATION_REASON = (
    "The Local IP API now supports system scope and default roles.")

rules = [
    policy.DocumentedRuleDefault(
        name='create_local_ip_port_association',
        check_str=neutron_policy.policy_or(
            base.ADMIN_OR_PROJECT_MEMBER,
            base.RULE_PARENT_OWNER),
        scope_types=['project'],
        description='Create a Local IP port association',
        operations=[
            {
                'method': 'POST',
                'path': COLLECTION_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='create_local_ip_port_association',
            check_str=neutron_policy.RULE_ADMIN_OR_PARENT_OWNER,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_local_ip_port_association',
        check_str=neutron_policy.policy_or(
            base.ADMIN_OR_PROJECT_READER,
            base.RULE_PARENT_OWNER),
        scope_types=['project'],
        description='Get a Local IP port association',
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
            name='get_local_ip_port_association',
            check_str=neutron_policy.RULE_ADMIN_OR_PARENT_OWNER,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='delete_local_ip_port_association',
        check_str=neutron_policy.policy_or(
            base.ADMIN_OR_PROJECT_MEMBER,
            base.RULE_PARENT_OWNER),
        scope_types=['project'],
        description='Delete a Local IP port association',
        operations=[
            {
                'method': 'DELETE',
                'path': RESOURCE_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_local_ip_port_association',
            check_str=neutron_policy.RULE_ADMIN_OR_PARENT_OWNER,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
]


def list_rules():
    return rules
