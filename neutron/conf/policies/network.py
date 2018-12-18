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


rules = [
    policy.RuleDefault(
        'external',
        'field:networks:router:external=True',
        description='Rule of external network'),

    policy.RuleDefault(
        'create_network',
        base.RULE_ANY,
        description='Access rule for creating network'),
    policy.RuleDefault(
        'create_network:shared',
        base.RULE_ADMIN_ONLY,
        description='Access rule for creating shared network'),
    policy.RuleDefault(
        'create_network:router:external',
        base.RULE_ADMIN_ONLY,
        description='Access rule for creating external network'),
    policy.RuleDefault(
        'create_network:is_default',
        base.RULE_ADMIN_ONLY,
        description='Access rule for creating network with is_default'),
    policy.RuleDefault(
        'create_network:segments',
        base.RULE_ADMIN_ONLY,
        description='Access rule for creating network with segments'),
    policy.RuleDefault(
        'create_network:provider:network_type',
        base.RULE_ADMIN_ONLY,
        description=('Access rule for creating network '
                     'with provider network_type')),
    policy.RuleDefault(
        'create_network:provider:physical_network',
        base.RULE_ADMIN_ONLY,
        description=('Access rule for creating network '
                     'with provider physical_network')),
    policy.RuleDefault(
        'create_network:provider:segmentation_id',
        base.RULE_ADMIN_ONLY,
        description=('Access rule for creating network '
                     'with provider segmentation_id')),

    policy.RuleDefault(
        'get_network',
        base.policy_or(base.RULE_ADMIN_OR_OWNER,
                       'rule:shared',
                       'rule:external',
                       base.RULE_ADVSVC),
        description='Access rule for getting shared network'),
    policy.RuleDefault(
        'get_network:router:external',
        base.RULE_ANY,
        description='Access rule for getting external network'),
    policy.RuleDefault(
        'get_network:segments',
        base.RULE_ADMIN_ONLY,
        description='Access rule for getting segments of network'),
    policy.RuleDefault(
        'get_network:provider:network_type',
        base.RULE_ADMIN_ONLY,
        description=('Access rule for getting provider '
                     'network_type of network')),
    policy.RuleDefault(
        'get_network:provider:physical_network',
        base.RULE_ADMIN_ONLY,
        description=('Access rule for getting provider '
                     'physical_network of network')),
    policy.RuleDefault(
        'get_network:provider:segmentation_id',
        base.RULE_ADMIN_ONLY,
        description=('Access rule for getting provider '
                     'segmentation_id of network')),

    policy.RuleDefault(
        'update_network',
        base.RULE_ADMIN_OR_OWNER,
        description='Access rule for updating network'),
    policy.RuleDefault(
        'update_network:segments',
        base.RULE_ADMIN_ONLY,
        description='Access rule for updating segments of network'),
    policy.RuleDefault(
        'update_network:shared',
        base.RULE_ADMIN_ONLY,
        description='Access rule for updating shared attribute of network'),
    policy.RuleDefault(
        'update_network:provider:network_type',
        base.RULE_ADMIN_ONLY,
        description=('Access rule for updating provider '
                     'network_type of network')),
    policy.RuleDefault(
        'update_network:provider:physical_network',
        base.RULE_ADMIN_ONLY,
        description=('Access rule for updating provider '
                     'physical_network of network')),
    policy.RuleDefault(
        'update_network:provider:segmentation_id',
        base.RULE_ADMIN_ONLY,
        description=('Access rule for updating provider '
                     'segmentation_id of network')),
    policy.RuleDefault(
        'update_network:router:external',
        base.RULE_ADMIN_ONLY,
        description=('Access rule for updating router:external attribute '
                     'of network')),

    policy.RuleDefault(
        'delete_network',
        base.RULE_ADMIN_OR_OWNER,
        description='Access rule for deleting network'),
]


def list_rules():
    return rules
