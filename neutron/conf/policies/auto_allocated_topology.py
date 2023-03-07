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


RESOURCE_PATH = '/auto-allocated-topology/{project_id}'

DEPRECATION_REASON = (
    "The Auto allocated topology API now supports system scope "
    "and default roles.")

rules = [
    policy.DocumentedRuleDefault(
        name='get_auto_allocated_topology',
        check_str=base.ADMIN_OR_PROJECT_READER,
        description="Get a project's auto-allocated topology",
        operations=[
            {
                'method': 'GET',
                'path': RESOURCE_PATH,
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='get_auto_allocated_topology',
            check_str=neutron_policy.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='delete_auto_allocated_topology',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        description="Delete a project's auto-allocated topology",
        operations=[
            {
                'method': 'DELETE',
                'path': RESOURCE_PATH,
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_auto_allocated_topology',
            check_str=neutron_policy.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
]


def list_rules():
    return rules
