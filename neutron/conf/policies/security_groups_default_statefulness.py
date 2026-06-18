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

from neutron_lib.policy import rules as lib_rules
from oslo_policy import policy


COLLECTION_PATH = '/security-groups-default-statefulness'
RESOURCE_PATH = '/security-groups-default-statefulness/{id}'


rules = [
    policy.DocumentedRuleDefault(
        name='create_security_groups_default_statefulness',
        check_str=lib_rules.ADMIN_OR_PROJECT_MANAGER,
        scope_types=['project'],
        description=(
            'Create a default statefulness setting for security groups. '
            'System-wide settings (no project_id) always require admin '
            'privileges. Per-project settings could be relaxed via '
            'policy override to allow creation by project owners.'),
        operations=[
            {
                'method': 'POST',
                'path': COLLECTION_PATH,
            },
        ],
    ),
    policy.DocumentedRuleDefault(
        name='get_security_groups_default_statefulness',
        check_str=lib_rules.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description=(
            'Get default statefulness settings for security groups. '
            'Admins can list all settings; project readers can see '
            'the setting for their own project.'),
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
    ),
    policy.DocumentedRuleDefault(
        name='update_security_groups_default_statefulness',
        check_str=lib_rules.ADMIN_OR_PROJECT_MANAGER,
        scope_types=['project'],
        description=(
            'Update a default statefulness setting for security groups. '
            'System-wide settings always require admin privileges. '
            'Per-project settings could be relaxed via policy override '
            'to allow update by project owners.'),
        operations=[
            {
                'method': 'PUT',
                'path': RESOURCE_PATH,
            },
        ],
    ),
    policy.DocumentedRuleDefault(
        name='delete_security_groups_default_statefulness',
        check_str=lib_rules.ADMIN_OR_PROJECT_MANAGER,
        scope_types=['project'],
        description=(
            'Delete a default statefulness setting for security groups. '
            'System-wide settings always require admin privileges. '
            'Per-project settings could be relaxed via policy override '
            'to allow deletion by project owners.'),
        operations=[
            {
                'method': 'DELETE',
                'path': RESOURCE_PATH,
            },
        ],
    ),
]


def list_rules():
    return rules
