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


DEPRECATION_REASON = (
    "The Service Providers API now supports project scope and default roles.")

rules = [
    policy.DocumentedRuleDefault(
        name='get_service_provider',
        # NOTE: it can't be ADMIN_OR_PROJECT_READER constant from the base
        # module because that is using "project_id" in the check string and the
        # service_provider resource don't belongs to any project thus such
        # check string would fail enforcement.
        check_str='role:reader',
        description='Get service providers',
        operations=[
            {
                'method': 'GET',
                'path': '/service-providers',
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='get_service_provider',
            check_str=neutron_policy.RULE_ANY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
]


def list_rules():
    return rules
