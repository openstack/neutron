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


FLAVOR_COLLECTION_PATH = '/flavors'
FLAVOR_RESOURCE_PATH = '/flavors/{id}'
PROFILE_COLLECTION_PATH = '/service_profiles'
PROFILE_RESOURCE_PATH = '/service_profiles/{id}'
ASSOC_COLLECTION_PATH = '/flavors/{flavor_id}/service_profiles'
ASSOC_RESOURCE_PATH = '/flavors/{flavor_id}/service_profiles/{profile_id}'

DEPRECATION_REASON = (
    "The flavor API now supports project scope and default roles.")


rules = [
    policy.DocumentedRuleDefault(
        name='create_flavor',
        check_str=base.ADMIN,
        description='Create a flavor',
        operations=[
            {
                'method': 'POST',
                'path': FLAVOR_COLLECTION_PATH,
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='create_flavor',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_flavor',
        # NOTE: it can't be ADMIN_OR_PROJECT_READER constant from the base
        # module because that is using "project_id" in the check string and the
        # service_provider resource don't belongs to any project thus such
        # check string would fail enforcement.
        check_str='role:reader',
        description='Get a flavor',
        operations=[
            {
                'method': 'GET',
                'path': FLAVOR_COLLECTION_PATH,
            },
            {
                'method': 'GET',
                'path': FLAVOR_RESOURCE_PATH,
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='get_flavor',
            check_str=base.RULE_ANY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_flavor',
        check_str=base.ADMIN,
        description='Update a flavor',
        operations=[
            {
                'method': 'PUT',
                'path': FLAVOR_RESOURCE_PATH,
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='update_flavor',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='delete_flavor',
        check_str=base.ADMIN,
        description='Delete a flavor',
        operations=[
            {
                'method': 'DELETE',
                'path': FLAVOR_RESOURCE_PATH,
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_flavor',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),

    policy.DocumentedRuleDefault(
        name='create_service_profile',
        check_str=base.ADMIN,
        description='Create a service profile',
        operations=[
            {
                'method': 'POST',
                'path': PROFILE_COLLECTION_PATH,
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='create_service_profile',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_service_profile',
        check_str=base.ADMIN,
        description='Get a service profile',
        operations=[
            {
                'method': 'GET',
                'path': PROFILE_COLLECTION_PATH,
            },
            {
                'method': 'GET',
                'path': PROFILE_RESOURCE_PATH,
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='get_service_profile',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_service_profile',
        check_str=base.ADMIN,
        description='Update a service profile',
        operations=[
            {
                'method': 'PUT',
                'path': PROFILE_RESOURCE_PATH,
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='update_service_profile',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='delete_service_profile',
        check_str=base.ADMIN,
        description='Delete a service profile',
        operations=[
            {
                'method': 'DELETE',
                'path': PROFILE_RESOURCE_PATH,
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_service_profile',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),

    policy.RuleDefault(
        name='get_flavor_service_profile',
        check_str=base.ADMIN_OR_PROJECT_READER,
        description=(
            'Get a flavor associated with a given service profiles. '
            'There is no corresponding GET operations in API currently. '
            'This rule is currently referred only in the DELETE '
            'of flavor_service_profile.'),
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='get_flavor_service_profile',
            check_str=base.RULE_ANY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_flavor_service_profile',
        check_str=base.ADMIN,
        description='Associate a flavor with a service profile',
        operations=[
            {
                'method': 'POST',
                'path': ASSOC_COLLECTION_PATH,
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='create_flavor_service_profile',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='delete_flavor_service_profile',
        check_str=base.ADMIN,
        description='Disassociate a flavor with a service profile',
        operations=[
            {
                'method': 'DELETE',
                'path': ASSOC_RESOURCE_PATH,
            },
        ],
        scope_types=['project'],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_flavor_service_profile',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATION_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
]


def list_rules():
    return rules
