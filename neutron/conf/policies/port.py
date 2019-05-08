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


COLLECTION_PATH = '/ports'
RESOURCE_PATH = '/ports/{id}'

ACTION_POST = [
    {'method': 'POST', 'path': COLLECTION_PATH},
]
ACTION_PUT = [
    {'method': 'PUT', 'path': RESOURCE_PATH},
]
ACTION_DELETE = [
    {'method': 'DELETE', 'path': RESOURCE_PATH},
]
ACTION_GET = [
    {'method': 'GET', 'path': COLLECTION_PATH},
    {'method': 'GET', 'path': RESOURCE_PATH},
]


rules = [
    policy.RuleDefault(
        'network_device',
        'field:port:device_owner=~^network:',
        'Definition of port with network device_owner'),
    policy.RuleDefault(
        'admin_or_data_plane_int',
        base.policy_or('rule:context_is_admin',
                       'role:data_plane_integrator'),
        'Rule for data plane integration'),

    policy.DocumentedRuleDefault(
        'create_port',
        base.RULE_ANY,
        'Create a port',
        ACTION_POST
    ),
    policy.DocumentedRuleDefault(
        'create_port:device_owner',
        base.policy_or('not rule:network_device',
                       base.RULE_ADVSVC,
                       base.RULE_ADMIN_OR_NET_OWNER),
        'Specify ``device_owner`` attribute when creting a port',
        ACTION_POST
    ),
    policy.DocumentedRuleDefault(
        'create_port:mac_address',
        base.policy_or(base.RULE_ADVSVC,
                       base.RULE_ADMIN_OR_NET_OWNER),
        'Specify ``mac_address`` attribute when creating a port',
        ACTION_POST
    ),
    policy.DocumentedRuleDefault(
        'create_port:fixed_ips',
        base.policy_or(base.RULE_ADVSVC,
                       base.RULE_ADMIN_OR_NET_OWNER,
                       'rule:shared'),
        'Specify ``fixed_ips`` information when creating a port',
        ACTION_POST
    ),
    policy.DocumentedRuleDefault(
        'create_port:fixed_ips:ip_address',
        base.policy_or(base.RULE_ADVSVC,
                       base.RULE_ADMIN_OR_NET_OWNER),
        'Specify IP address in ``fixed_ips`` when creating a port',
        ACTION_POST
    ),
    policy.DocumentedRuleDefault(
        'create_port:fixed_ips:subnet_id',
        base.policy_or(base.RULE_ADVSVC,
                       base.RULE_ADMIN_OR_NET_OWNER,
                       'rule:shared'),
        'Specify subnet ID in ``fixed_ips`` when creating a port',
        ACTION_POST
    ),
    policy.DocumentedRuleDefault(
        'create_port:port_security_enabled',
        base.policy_or(base.RULE_ADVSVC,
                       base.RULE_ADMIN_OR_NET_OWNER),
        'Specify ``port_security_enabled`` attribute when creating a port',
        ACTION_POST
    ),
    policy.DocumentedRuleDefault(
        'create_port:binding:host_id',
        base.RULE_ADMIN_ONLY,
        'Specify ``binding:host_id`` attribute when creating a port',
        ACTION_POST
    ),
    policy.DocumentedRuleDefault(
        'create_port:binding:profile',
        base.RULE_ADMIN_ONLY,
        'Specify ``binding:profile`` attribute when creating a port',
        ACTION_POST
    ),
    policy.DocumentedRuleDefault(
        'create_port:binding:vnic_type',
        base.RULE_ANY,
        'Specify ``binding:vnic_type`` attribute when creating a port',
        ACTION_POST
    ),
    policy.DocumentedRuleDefault(
        'create_port:allowed_address_pairs',
        base.RULE_ADMIN_OR_NET_OWNER,
        'Specify ``allowed_address_pairs`` attribute when creating a port',
        ACTION_POST
    ),
    policy.DocumentedRuleDefault(
        'create_port:allowed_address_pairs:mac_address',
        base.RULE_ADMIN_OR_NET_OWNER,
        ('Specify ``mac_address` of `allowed_address_pairs`` '
         'attribute when creating a port'),
        ACTION_POST
    ),
    policy.DocumentedRuleDefault(
        'create_port:allowed_address_pairs:ip_address',
        base.RULE_ADMIN_OR_NET_OWNER,
        ('Specify ``ip_address`` of ``allowed_address_pairs`` '
         'attribute when creating a port'),
        ACTION_POST
    ),

    policy.DocumentedRuleDefault(
        'get_port',
        base.policy_or(base.RULE_ADVSVC,
                       'rule:admin_owner_or_network_owner'),
        'Get a port',
        ACTION_GET
    ),
    policy.DocumentedRuleDefault(
        'get_port:binding:vif_type',
        base.RULE_ADMIN_ONLY,
        'Get ``binding:vif_type`` attribute of a port',
        ACTION_GET
    ),
    policy.DocumentedRuleDefault(
        'get_port:binding:vif_details',
        base.RULE_ADMIN_ONLY,
        'Get ``binding:vif_details`` attribute of a port',
        ACTION_GET
    ),
    policy.DocumentedRuleDefault(
        'get_port:binding:host_id',
        base.RULE_ADMIN_ONLY,
        'Get ``binding:host_id`` attribute of a port',
        ACTION_GET
    ),
    policy.DocumentedRuleDefault(
        'get_port:binding:profile',
        base.RULE_ADMIN_ONLY,
        'Get ``binding:profile`` attribute of a port',
        ACTION_GET
    ),
    policy.DocumentedRuleDefault(
        'get_port:resource_request',
        base.RULE_ADMIN_ONLY,
        'Get ``resource_request`` attribute of a port',
        ACTION_GET
    ),
    # TODO(amotoki): Add get_port:binding:vnic_type
    # TODO(amotoki): Add get_port:binding:data_plane_status

    policy.DocumentedRuleDefault(
        'update_port',
        base.policy_or(base.RULE_ADMIN_OR_OWNER,
                       base.RULE_ADVSVC),
        'Update a port',
        ACTION_PUT
    ),
    policy.DocumentedRuleDefault(
        'update_port:device_owner',
        base.policy_or('not rule:network_device',
                       base.RULE_ADVSVC,
                       base.RULE_ADMIN_OR_NET_OWNER),
        'Update ``device_owner`` attribute of a port',
        ACTION_PUT
    ),
    policy.DocumentedRuleDefault(
        'update_port:mac_address',
        base.policy_or(base.RULE_ADMIN_ONLY,
                       base.RULE_ADVSVC),
        'Update ``mac_address`` attribute of a port',
        ACTION_PUT
    ),
    policy.DocumentedRuleDefault(
        'update_port:fixed_ips',
        base.policy_or(base.RULE_ADVSVC,
                       base.RULE_ADMIN_OR_NET_OWNER),
        'Specify ``fixed_ips`` information when updating a port',
        ACTION_PUT
    ),
    policy.DocumentedRuleDefault(
        'update_port:fixed_ips:ip_address',
        base.policy_or(base.RULE_ADVSVC,
                       base.RULE_ADMIN_OR_NET_OWNER),
        'Specify IP address in ``fixed_ips`` information when updating a port',
        ACTION_PUT
    ),
    policy.DocumentedRuleDefault(
        'update_port:fixed_ips:subnet_id',
        base.policy_or(base.RULE_ADVSVC,
                       base.RULE_ADMIN_OR_NET_OWNER,
                       'rule:shared'),
        'Specify subnet ID in ``fixed_ips`` information when updating a port',
        ACTION_PUT
    ),
    policy.DocumentedRuleDefault(
        'update_port:port_security_enabled',
        base.policy_or(base.RULE_ADVSVC,
                       base.RULE_ADMIN_OR_NET_OWNER),
        'Update ``port_security_enabled`` attribute of a port',
        ACTION_PUT
    ),
    policy.DocumentedRuleDefault(
        'update_port:binding:host_id',
        base.RULE_ADMIN_ONLY,
        'Update ``binding:host_id`` attribute of a port',
        ACTION_PUT
    ),
    policy.DocumentedRuleDefault(
        'update_port:binding:profile',
        base.RULE_ADMIN_ONLY,
        'Update ``binding:profile`` attribute of a port',
        ACTION_PUT
    ),
    policy.DocumentedRuleDefault(
        'update_port:binding:vnic_type',
        base.policy_or(base.RULE_ADMIN_OR_OWNER,
                       base.RULE_ADVSVC),
        'Update ``binding:vnic_type`` attribute of a port',
        ACTION_PUT
    ),
    policy.DocumentedRuleDefault(
        'update_port:allowed_address_pairs',
        base.RULE_ADMIN_OR_NET_OWNER,
        'Update ``allowed_address_pairs`` attribute of a port',
        ACTION_PUT
    ),
    policy.DocumentedRuleDefault(
        'update_port:allowed_address_pairs:mac_address',
        base.RULE_ADMIN_OR_NET_OWNER,
        ('Update ``mac_address`` of ``allowed_address_pairs`` '
         'attribute of a port'),
        ACTION_PUT
    ),
    policy.DocumentedRuleDefault(
        'update_port:allowed_address_pairs:ip_address',
        base.RULE_ADMIN_OR_NET_OWNER,
        ('Update ``ip_address`` of ``allowed_address_pairs`` '
         'attribute of a port'),
        ACTION_PUT
    ),
    policy.DocumentedRuleDefault(
        'update_port:data_plane_status',
        'rule:admin_or_data_plane_int',
        'Update ``data_plane_status`` attribute of a port',
        ACTION_PUT
    ),

    policy.DocumentedRuleDefault(
        'delete_port',
        base.policy_or(base.RULE_ADVSVC,
                       'rule:admin_owner_or_network_owner'),
        'Delete a port',
        ACTION_DELETE
    ),
]


def list_rules():
    return rules
