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


rules = [
    policy.RuleDefault(
        'context_is_admin',
        'role:admin',
        description='Rule for cloud admin access'),
    policy.RuleDefault(
        'owner',
        'tenant_id:%(tenant_id)s',
        description='Rule for resource owner access'),
    policy.RuleDefault(
        'admin_or_owner',
        'rule:context_is_admin or rule:owner',
        description='Rule for admin or owner access'),
    policy.RuleDefault(
        'context_is_advsvc',
        'role:advsvc',
        description='Rule for advsvc role access'),
    policy.RuleDefault(
        'admin_or_network_owner',
        'rule:context_is_admin or tenant_id:%(network:tenant_id)s',
        description='Rule for admin or network owner access'),
    policy.RuleDefault(
        'admin_owner_or_network_owner',
        'rule:owner or rule:admin_or_network_owner',
        description=('Rule for resource owner, '
                     'admin or network owner access')),
    policy.RuleDefault(
        'admin_only',
        'rule:context_is_admin',
        description='Rule only for admin access'),
    policy.RuleDefault(
        'regular_user',
        '',
        description='Rule for regular user access'),
    # TODO(amotoki): Should be renamed to shared_network? It seems clearer.
    policy.RuleDefault(
        'shared',
        'field:networks:shared=True',
        description='Rule of shared network'),
    policy.RuleDefault(
        'default',
        'rule:admin_or_owner',
        description='Default access rule'),
    policy.RuleDefault(
        'admin_or_ext_parent_owner',
        'rule:context_is_admin or tenant_id:%(ext_parent:tenant_id)s',
        description='Rule for common parent owner check'),
]


def list_rules():
    return rules
