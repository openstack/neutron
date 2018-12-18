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
        'network_device',
        'field:port:device_owner=~^network:',
        description='Rule of port with network device_owner'),
    policy.RuleDefault(
        'admin_or_data_plane_int',
        base.policy_or('rule:context_is_admin',
                       'role:data_plane_integrator'),
        description='Rule for data plane integration'),

    policy.RuleDefault(
        'create_port',
        base.RULE_ANY,
        description='Access rule for creating port'),
    policy.RuleDefault(
        'create_port:device_owner',
        base.policy_or('not rule:network_device',
                       base.RULE_ADVSVC,
                       base.RULE_ADMIN_OR_NET_OWNER),
        description='Access rule for creating port with device_owner'),
    policy.RuleDefault(
        'create_port:mac_address',
        base.policy_or(base.RULE_ADVSVC,
                       base.RULE_ADMIN_OR_NET_OWNER),
        description=('Access rule for creating port with mac_address')),
    policy.RuleDefault(
        'create_port:fixed_ips',
        base.policy_or(base.RULE_ADVSVC,
                       base.RULE_ADMIN_OR_NET_OWNER),
        description='Access rule for creating port with fixed_ips'),
    policy.RuleDefault(
        'create_port:fixed_ips:ip_address',
        base.policy_or(base.RULE_ADVSVC,
                       base.RULE_ADMIN_OR_NET_OWNER),
        description=('Access rule for creating port specifying IP address in '
                     'fixed_ips')),
    policy.RuleDefault(
        'create_port:fixed_ips:subnet_id',
        base.policy_or(base.RULE_ADVSVC,
                       base.RULE_ADMIN_OR_NET_OWNER,
                       'rule:shared'),
        description=('Access rule for creating port specifying subnet ID in '
                     'fixed_ips')),
    policy.RuleDefault(
        'create_port:port_security_enabled',
        base.policy_or(base.RULE_ADVSVC,
                       base.RULE_ADMIN_OR_NET_OWNER),
        description=('Access rule for creating '
                     'port with port_security_enabled')),
    policy.RuleDefault(
        'create_port:binding:host_id',
        base.RULE_ADMIN_ONLY,
        description=('Access rule for creating '
                     'port with binging host_id')),
    policy.RuleDefault(
        'create_port:binding:profile',
        base.RULE_ADMIN_ONLY,
        description=('Access rule for creating '
                     'port with binding profile')),
    # TODO(amotoki): Add create_port:binding:vnic_type
    policy.RuleDefault(
        'create_port:allowed_address_pairs',
        base.RULE_ADMIN_OR_NET_OWNER,
        description=('Access rule for creating port '
                     'with allowed_address_pairs attribute')),

    policy.RuleDefault(
        'get_port',
        base.policy_or(base.RULE_ADVSVC,
                       'rule:admin_owner_or_network_owner'),
        description='Access rule for getting port'),
    policy.RuleDefault(
        'get_port:binding:vif_type',
        base.RULE_ADMIN_ONLY,
        description='Access rule for getting binding vif_type of port'),
    policy.RuleDefault(
        'get_port:binding:vif_details',
        base.RULE_ADMIN_ONLY,
        description='Access rule for getting binding vif_details of port'),
    policy.RuleDefault(
        'get_port:binding:host_id',
        base.RULE_ADMIN_ONLY,
        description='Access rule for getting binding host_id of port'),
    policy.RuleDefault(
        'get_port:binding:profile',
        base.RULE_ADMIN_ONLY,
        description='Access rule for getting binding profile of port'),
    # TODO(amotoki): Add get_port:binding:vnic_type
    # TODO(amotoki): Add get_port:binding:data_plane_status

    policy.RuleDefault(
        'update_port',
        base.policy_or(base.RULE_ADMIN_OR_OWNER,
                       base.RULE_ADVSVC),
        description='Access rule for updating port'),
    policy.RuleDefault(
        'update_port:device_owner',
        base.policy_or('not rule:network_device',
                       base.RULE_ADVSVC,
                       base.RULE_ADMIN_OR_NET_OWNER),
        description='Access rule for updating device_owner of port'),
    policy.RuleDefault(
        'update_port:mac_address',
        base.policy_or(base.RULE_ADMIN_ONLY,
                       base.RULE_ADVSVC),
        description='Access rule for updating mac_address of port'),
    policy.RuleDefault(
        'update_port:fixed_ips',
        base.policy_or(base.RULE_ADVSVC,
                       base.RULE_ADMIN_OR_NET_OWNER),
        description='Access rule for updating fixed_ips of port'),
    policy.RuleDefault(
        'update_port:fixed_ips:ip_address',
        base.policy_or(base.RULE_ADVSVC,
                       base.RULE_ADMIN_OR_NET_OWNER),
        description=('Access rule for updating port specifying IP address in '
                     'fixed_ips')),
    policy.RuleDefault(
        'update_port:fixed_ips:subnet_id',
        base.policy_or(base.RULE_ADVSVC,
                       base.RULE_ADMIN_OR_NET_OWNER,
                       'rule:shared'),
        description=('Access rule for updating port specifying subnet ID in '
                     'fixed_ips')),
    policy.RuleDefault(
        'update_port:port_security_enabled',
        base.policy_or(base.RULE_ADVSVC,
                       base.RULE_ADMIN_OR_NET_OWNER),
        description='Access rule for updating port_security_enabled of port'),
    policy.RuleDefault(
        'update_port:binding:host_id',
        base.RULE_ADMIN_ONLY,
        description='Access rule for updating binding host_id of port'),
    policy.RuleDefault(
        'update_port:binding:profile',
        base.RULE_ADMIN_ONLY,
        description='Access rule for updating binding profile of port'),
    # TODO(amotoki): Add update_port:binding:vnic_type
    policy.RuleDefault(
        'update_port:allowed_address_pairs',
        base.RULE_ADMIN_OR_NET_OWNER,
        description='Access rule for updating allowed_address_pairs of port'),
    policy.RuleDefault(
        'update_port:data_plane_status',
        'rule:admin_or_data_plane_int',
        description='Access rule for updating data_plane_status of port'),

    policy.RuleDefault(
        'delete_port',
        base.policy_or(base.RULE_ADVSVC,
                       'rule:admin_owner_or_network_owner'),
        description='Access rule for deleting port'),
]


def list_rules():
    return rules
