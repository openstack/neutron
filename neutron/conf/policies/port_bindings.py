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


BINDING_PATH = '/ports/{port_id}/bindings/'
ACTIVATE_BINDING_PATH = '/ports/{port_id}/bindings/{host}'


rules = [
    policy.DocumentedRuleDefault(
        name='get_port_binding',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Get port binding information',
        operations=[
            {
                'method': 'GET',
                'path': BINDING_PATH,
            },
        ],
    ),
    policy.DocumentedRuleDefault(
        name='create_port_binding',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Create port binding on the host',
        operations=[
            {
                'method': 'POST',
                'path': BINDING_PATH,
            },
        ],
    ),
    policy.DocumentedRuleDefault(
        name='delete_port_binding',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Delete port binding on the host',
        operations=[
            {
                'method': 'DELETE',
                'path': BINDING_PATH,
            },
        ],
    ),
    policy.DocumentedRuleDefault(
        name='activate',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Activate port binding on the host',
        operations=[
            {
                'method': 'PUT',
                'path': ACTIVATE_BINDING_PATH,
            },
        ],
    ),
]


def list_rules():
    return rules
