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
    policy.RuleDefault('get_agent',
                       base.RULE_ADMIN_ONLY,
                       description='Access rule for getting agent'),
    policy.RuleDefault('update_agent',
                       base.RULE_ADMIN_ONLY,
                       description='Access rule for updating agent'),
    policy.RuleDefault('delete_agent',
                       base.RULE_ADMIN_ONLY,
                       description='Access rule for deleting agent'),
    policy.RuleDefault('create_dhcp-network',
                       base.RULE_ADMIN_ONLY,
                       description=('Access rule for adding '
                                    'network to dhcp agent')),
    policy.RuleDefault('get_dhcp-networks',
                       base.RULE_ADMIN_ONLY,
                       description=('Access rule for listing '
                                    'networks on the dhcp agent')),
    policy.RuleDefault('delete_dhcp-network',
                       base.RULE_ADMIN_ONLY,
                       description=('Access rule for removing '
                                    'network from dhcp agent')),
    policy.RuleDefault('create_l3-router',
                       base.RULE_ADMIN_ONLY,
                       description=('Access rule for adding '
                                    'router to l3 agent')),
    policy.RuleDefault('get_l3-routers',
                       base.RULE_ADMIN_ONLY,
                       description=('Access rule for listing '
                                    'routers on the l3 agent')),
    policy.RuleDefault('delete_l3-router',
                       base.RULE_ADMIN_ONLY,
                       description=('Access rule for deleting '
                                    'router from l3 agent')),
    policy.RuleDefault('get_dhcp-agents',
                       base.RULE_ADMIN_ONLY,
                       description=('Access rule for listing '
                                    'dhcp agents hosting the network')),
    policy.RuleDefault('get_l3-agents',
                       base.RULE_ADMIN_ONLY,
                       description=('Access rule for listing '
                                    'l3 agents hosting the router')),
    # TODO(amotoki): Remove LBaaS related policies once neutron-lbaas
    # is retired.
    policy.RuleDefault('get_loadbalancer-agent',
                       base.RULE_ADMIN_ONLY,
                       description=('Access rule for getting '
                                    'lbaas agent hosting the pool')),
    policy.RuleDefault('get_loadbalancer-pools',
                       base.RULE_ADMIN_ONLY,
                       description=('Access rule for listing '
                                    'pools on the lbaas agent')),
    policy.RuleDefault('get_agent-loadbalancers',
                       base.RULE_ADMIN_ONLY,
                       description=('Access rule for listing '
                                    'loadbalancers on the lbaasv2 agent')),
    policy.RuleDefault('get_loadbalancer-hosting-agent',
                       base.RULE_ADMIN_ONLY,
                       description=('Access rule for getting '
                                    'lbaasv2 agent hosting the loadbalancer')),
]


def list_rules():
    return rules
