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

DEPRECATED_REASON = (
    "The Floating IP Pool API now supports system scope and default roles.")

rules = [
    policy.DocumentedRuleDefault(
        name='get_floatingip_pool',
        check_str=base.ADMIN_OR_PROJECT_READER,
        description='Get floating IP pools',
        operations=[
            {
                'method': 'GET',
                'path': '/floatingip_pools',
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='get_floatingip_pool',
            check_str=base.RULE_ANY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
]


def list_rules():
    return rules
