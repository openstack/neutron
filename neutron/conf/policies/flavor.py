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


FLAVOR_COLLECTION_PATH = '/flavors'
FLAVOR_RESOURCE_PATH = '/flavors/{id}'
PROFILE_COLLECTION_PATH = '/service_profiles'
PROFILE_RESOURCE_PATH = '/service_profiles/{id}'
ASSOC_COLLECTION_PATH = '/flavors/{flavor_id}/service_profiles'
ASSOC_RESOURCE_PATH = '/flavors/{flavor_id}/service_profiles/{profile_id}'


rules = [
    policy.DocumentedRuleDefault(
        'create_flavor',
        base.RULE_ADMIN_ONLY,
        'Create a flavor',
        [
            {
                'method': 'POST',
                'path': FLAVOR_COLLECTION_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'get_flavor',
        base.RULE_ANY,
        'Get a flavor',
        [
            {
                'method': 'GET',
                'path': FLAVOR_COLLECTION_PATH,
            },
            {
                'method': 'GET',
                'path': FLAVOR_RESOURCE_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_flavor',
        base.RULE_ADMIN_ONLY,
        'Update a flavor',
        [
            {
                'method': 'PUT',
                'path': FLAVOR_RESOURCE_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_flavor',
        base.RULE_ADMIN_ONLY,
        'Delete a flavor',
        [
            {
                'method': 'DELETE',
                'path': FLAVOR_RESOURCE_PATH,
            },
        ]
    ),

    policy.DocumentedRuleDefault(
        'create_service_profile',
        base.RULE_ADMIN_ONLY,
        'Create a service profile',
        [
            {
                'method': 'POST',
                'path': PROFILE_COLLECTION_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'get_service_profile',
        base.RULE_ADMIN_ONLY,
        'Get a service profile',
        [
            {
                'method': 'GET',
                'path': PROFILE_COLLECTION_PATH,
            },
            {
                'method': 'GET',
                'path': PROFILE_RESOURCE_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_service_profile',
        base.RULE_ADMIN_ONLY,
        'Update a service profile',
        [
            {
                'method': 'PUT',
                'path': PROFILE_RESOURCE_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_service_profile',
        base.RULE_ADMIN_ONLY,
        'Delete a service profile',
        [
            {
                'method': 'DELETE',
                'path': PROFILE_RESOURCE_PATH,
            },
        ]
    ),

    policy.RuleDefault(
        'get_flavor_service_profile',
        base.RULE_ANY,
        ('Get a flavor associated with a given service profiles. '
         'There is no corresponding GET operations in API currently. '
         'This rule is currently referred only in the DELETE '
         'of flavor_service_profile.')
    ),
    policy.DocumentedRuleDefault(
        'create_flavor_service_profile',
        base.RULE_ADMIN_ONLY,
        'Associate a flavor with a service profile',
        [
            {
                'method': 'POST',
                'path': ASSOC_COLLECTION_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_flavor_service_profile',
        base.RULE_ADMIN_ONLY,
        'Disassociate a flavor with a service profile',
        [
            {
                'method': 'DELETE',
                'path': ASSOC_RESOURCE_PATH,
            },
        ]
    ),
]


def list_rules():
    return rules
