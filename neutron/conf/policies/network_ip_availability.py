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

DEPRECATED_REASON = """
The network IP availability API now support project scope and default roles.
"""


rules = [
    policy.DocumentedRuleDefault(
        name='get_network_ip_availability',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Get network IP availability',
        operations=[
            {
                'method': 'GET',
                'path': '/network-ip-availabilities',
            },
            {
                'method': 'GET',
                'path': '/network-ip-availabilities/{network_id}',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='get_network_ip_availability',
            check_str=neutron_policy.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
]


def list_rules():
    return rules
