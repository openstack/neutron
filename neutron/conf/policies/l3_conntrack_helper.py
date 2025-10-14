# Copyright (c) 2019 Red Hat, Inc.
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
The router conntrack API now supports system scope and default roles.
"""

COLLECTION_PATH = '/routers/{router_id}/conntrack_helpers'
RESOURCE_PATH = ('/routers/{router_id}'
                 '/conntrack_helpers/{conntrack_helper_id}')


rules = [
    policy.DocumentedRuleDefault(
        name='create_router_conntrack_helper',
        check_str=base.ADMIN_OR_PARENT_OWNER_MEMBER,
        scope_types=['project'],
        description='Create a router conntrack helper',
        operations=[
            {
                'method': 'POST',
                'path': COLLECTION_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='create_router_conntrack_helper',
            check_str=neutron_policy.RULE_ADMIN_OR_PARENT_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_router_conntrack_helper',
        check_str=base.ADMIN_OR_PARENT_OWNER_READER,
        scope_types=['project'],
        description='Get a router conntrack helper',
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
        deprecated_rule=policy.DeprecatedRule(
            name='get_router_conntrack_helper',
            check_str=neutron_policy.RULE_ADMIN_OR_PARENT_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_router_conntrack_helper',
        check_str=base.ADMIN_OR_PARENT_OWNER_MEMBER,
        scope_types=['project'],
        description='Update a router conntrack helper',
        operations=[
            {
                'method': 'PUT',
                'path': RESOURCE_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='update_router_conntrack_helper',
            check_str=neutron_policy.RULE_ADMIN_OR_PARENT_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='delete_router_conntrack_helper',
        check_str=base.ADMIN_OR_PARENT_OWNER_MEMBER,
        scope_types=['project'],
        description='Delete a router conntrack helper',
        operations=[
            {
                'method': 'DELETE',
                'path': RESOURCE_PATH,
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_router_conntrack_helper',
            check_str=neutron_policy.RULE_ADMIN_OR_PARENT_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
]


def list_rules():
    return rules
