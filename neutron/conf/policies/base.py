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


def policy_and(*args):
    return ' and '.join(args)


def policy_or(*args):
    return ' or '.join(args)


# TODO(amotoki): Define these in neutron-lib once what constants are required
# from stadium and 3rd party projects.
# As of now, the following are candidates.
RULE_ADMIN_OR_OWNER = 'rule:admin_or_owner'
RULE_ADMIN_ONLY = 'rule:admin_only'
RULE_ANY = 'rule:regular_user'
RULE_ADVSVC = 'rule:context_is_advsvc'
RULE_ADMIN_OR_NET_OWNER = 'rule:admin_or_network_owner'
RULE_ADMIN_OR_NET_OWNER_OR_ADVSVC = policy_or(RULE_ADMIN_OR_NET_OWNER,
                                              RULE_ADVSVC)
RULE_ADMIN_OR_PARENT_OWNER = 'rule:admin_or_ext_parent_owner'


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
        policy_or('rule:context_is_admin',
                  'rule:owner'),
        description='Rule for admin or owner access'),
    policy.RuleDefault(
        'context_is_advsvc',
        'role:advsvc',
        description='Rule for advsvc role access'),
    policy.RuleDefault(
        'admin_or_network_owner',
        policy_or('rule:context_is_admin',
                  'tenant_id:%(network:tenant_id)s'),
        description='Rule for admin or network owner access'),
    policy.RuleDefault(
        'admin_owner_or_network_owner',
        policy_or('rule:owner',
                  RULE_ADMIN_OR_NET_OWNER),
        description=('Rule for resource owner, '
                     'admin or network owner access')),
    policy.RuleDefault(
        'admin_only',
        'rule:context_is_admin',
        description='Rule for admin-only access'),
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
        RULE_ADMIN_OR_OWNER,
        description='Default access rule'),
    policy.RuleDefault(
        'admin_or_ext_parent_owner',
        policy_or('rule:context_is_admin',
                  'tenant_id:%(ext_parent:tenant_id)s'),
        description='Rule for common parent owner check'),
]


def list_rules():
    return rules
