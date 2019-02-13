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


RESOURCE_PATH = '/auto-allocated-topology/{project_id}'


rules = [
    policy.DocumentedRuleDefault(
        'get_auto_allocated_topology',
        base.RULE_ADMIN_OR_OWNER,
        "Get a project's auto-allocated topology",
        [
            {
                'method': 'GET',
                'path': RESOURCE_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_auto_allocated_topology',
        base.RULE_ADMIN_OR_OWNER,
        "Delete a project's auto-allocated topology",
        [
            {
                'method': 'DELETE',
                'path': RESOURCE_PATH,
            },
        ]
    ),
]


def list_rules():
    return rules
