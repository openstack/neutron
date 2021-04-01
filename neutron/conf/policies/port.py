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

from oslo_log import versionutils
from oslo_policy import policy

from neutron.conf.policies import base

DEPRECATED_REASON = (
    "The port API now supports system scope and default roles.")


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
        name='network_device',
        check_str='field:port:device_owner=~^network:',
        description='Definition of port with network device_owner'),
    policy.RuleDefault(
        name='admin_or_data_plane_int',
        check_str=base.policy_or(
            'rule:context_is_admin',
            'role:data_plane_integrator'),
        description='Rule for data plane integration'),

    policy.DocumentedRuleDefault(
        name='create_port',
        check_str=base.SYSTEM_ADMIN_OR_PROJECT_MEMBER,
        scope_types=['system', 'project'],
        description='Create a port',
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_port',
            check_str=base.RULE_ANY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_port:device_owner',
        check_str=base.policy_or(
            'not rule:network_device',
            base.SYSTEM_ADMIN,
            base.PROJECT_ADMIN,
            base.RULE_ADVSVC,
            base.RULE_NET_OWNER
        ),
        scope_types=['system', 'project'],
        description='Specify ``device_owner`` attribute when creting a port',
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_port:device_owner',
            check_str=base.policy_or(
                'not rule:network_device',
                base.RULE_ADVSVC,
                base.RULE_ADMIN_OR_NET_OWNER),
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_port:mac_address',
        check_str=base.policy_or(
            base.RULE_ADVSVC,
            base.RULE_NET_OWNER,
            base.SYSTEM_ADMIN,
            base.PROJECT_ADMIN),
        scope_types=['system', 'project'],
        description='Specify ``mac_address`` attribute when creating a port',
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_port:mac_address',
            check_str=base.policy_or(
                base.RULE_ADVSVC,
                base.RULE_ADMIN_OR_NET_OWNER),
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_port:fixed_ips',
        check_str=base.policy_or(
            base.RULE_ADVSVC,
            base.RULE_NET_OWNER,
            base.SYSTEM_ADMIN,
            base.PROJECT_ADMIN,
            'rule:shared'),
        scope_types=['system', 'project'],
        description='Specify ``fixed_ips`` information when creating a port',
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_port:fixed_ips',
            check_str=base.policy_or(
                base.RULE_ADVSVC,
                base.RULE_ADMIN_OR_NET_OWNER,
                'rule:shared'),
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_port:fixed_ips:ip_address',
        check_str=base.policy_or(
            base.RULE_ADVSVC,
            base.RULE_NET_OWNER,
            base.SYSTEM_ADMIN,
            base.PROJECT_ADMIN),
        scope_types=['system', 'project'],
        description='Specify IP address in ``fixed_ips`` when creating a port',
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_port:fixed_ips:ip_address',
            check_str=base.policy_or(
                base.RULE_ADVSVC,
                base.RULE_ADMIN_OR_NET_OWNER),
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_port:fixed_ips:subnet_id',
        check_str=base.policy_or(
            base.RULE_ADVSVC,
            base.RULE_NET_OWNER,
            base.SYSTEM_ADMIN,
            base.PROJECT_ADMIN,
            'rule:shared'),
        scope_types=['system', 'project'],
        description='Specify subnet ID in ``fixed_ips`` when creating a port',
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_port:fixed_ips:subnet_id',
            check_str=base.policy_or(
                base.RULE_ADVSVC,
                base.RULE_ADMIN_OR_NET_OWNER,
                'rule:shared'),
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_port:port_security_enabled',
        check_str=base.policy_or(
            base.RULE_ADVSVC,
            base.RULE_NET_OWNER,
            base.SYSTEM_ADMIN,
            base.PROJECT_ADMIN),
        scope_types=['system', 'project'],
        description=(
            'Specify ``port_security_enabled`` '
            'attribute when creating a port'
        ),
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_port:port_security_enabled',
            check_str=base.policy_or(
                base.RULE_ADVSVC,
                base.RULE_ADMIN_OR_NET_OWNER),
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_port:binding:host_id',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description=(
            'Specify ``binding:host_id`` '
            'attribute when creating a port'
        ),
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_port:binding:host_id',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_port:binding:profile',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description=(
            'Specify ``binding:profile`` attribute '
            'when creating a port'
        ),
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_port:binding:profile',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_port:binding:vnic_type',
        check_str=base.SYSTEM_ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description=(
            'Specify ``binding:vnic_type`` '
            'attribute when creating a port'
        ),
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_port:binding:vnic_type',
            check_str=base.RULE_ANY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_port:allowed_address_pairs',
        check_str=base.policy_or(
            base.SYSTEM_ADMIN,
            base.PROJECT_ADMIN,
            base.RULE_NET_OWNER),
        scope_types=['project', 'system'],
        description=(
            'Specify ``allowed_address_pairs`` '
            'attribute when creating a port'
        ),
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_port:allowed_address_pairs',
            check_str=base.RULE_ADMIN_OR_NET_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_port:allowed_address_pairs:mac_address',
        check_str=base.policy_or(
            base.SYSTEM_ADMIN,
            base.PROJECT_ADMIN,
            base.RULE_NET_OWNER),
        scope_types=['project', 'system'],
        description=(
            'Specify ``mac_address` of `allowed_address_pairs`` '
            'attribute when creating a port'
        ),
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_port:allowed_address_pairs:mac_address',
            check_str=base.RULE_ADMIN_OR_NET_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='create_port:allowed_address_pairs:ip_address',
        check_str=base.policy_or(
            base.SYSTEM_ADMIN,
            base.PROJECT_ADMIN,
            base.RULE_NET_OWNER),
        scope_types=['project', 'system'],
        description=(
            'Specify ``ip_address`` of ``allowed_address_pairs`` '
            'attribute when creating a port'
        ),
        operations=ACTION_POST,
        deprecated_rule=policy.DeprecatedRule(
            name='create_port:allowed_address_pairs:ip_address',
            check_str=base.RULE_ADMIN_OR_NET_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),

    policy.DocumentedRuleDefault(
        name='get_port',
        check_str=base.policy_or(
            base.RULE_ADVSVC,
            base.SYSTEM_OR_PROJECT_READER
        ),
        scope_types=['project', 'system'],
        description='Get a port',
        operations=ACTION_GET,
        deprecated_rule=policy.DeprecatedRule(
            name='get_port',
            check_str=base.policy_or(
                base.RULE_ADVSVC,
                'rule:admin_owner_or_network_owner'),
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_port:binding:vif_type',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description='Get ``binding:vif_type`` attribute of a port',
        operations=ACTION_GET,
        deprecated_rule=policy.DeprecatedRule(
            name='get_port:binding:vif_type',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_port:binding:vif_details',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description='Get ``binding:vif_details`` attribute of a port',
        operations=ACTION_GET,
        deprecated_rule=policy.DeprecatedRule(
            name='get_port:binding:vif_details',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_port:binding:host_id',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description='Get ``binding:host_id`` attribute of a port',
        operations=ACTION_GET,
        deprecated_rule=policy.DeprecatedRule(
            name='get_port:binding:host_id',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_port:binding:profile',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description='Get ``binding:profile`` attribute of a port',
        operations=ACTION_GET,
        deprecated_rule=policy.DeprecatedRule(
            name='get_port:binding:profile',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='get_port:resource_request',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description='Get ``resource_request`` attribute of a port',
        operations=ACTION_GET,
        deprecated_rule=policy.DeprecatedRule(
            name='get_port:resource_request',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    # TODO(amotoki): Add get_port:binding:vnic_type
    # TODO(amotoki): Add get_port:binding:data_plane_status

    policy.DocumentedRuleDefault(
        name='update_port',
        check_str=base.policy_or(
            base.SYSTEM_ADMIN_OR_PROJECT_MEMBER,
            base.RULE_ADVSVC
        ),
        scope_types=['system', 'project'],
        description='Update a port',
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_port',
            check_str=base.policy_or(
                base.RULE_ADMIN_OR_OWNER,
                base.RULE_ADVSVC),
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_port:device_owner',
        check_str=base.policy_or(
            'not rule:network_device',
            base.RULE_ADVSVC,
            base.RULE_NET_OWNER,
            base.SYSTEM_ADMIN,
            base.PROJECT_ADMIN
        ),
        scope_types=['system', 'project'],
        description='Update ``device_owner`` attribute of a port',
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_port:device_owner',
            check_str=base.policy_or(
                'not rule:network_device',
                base.RULE_ADVSVC,
                base.RULE_ADMIN_OR_NET_OWNER),
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_port:mac_address',
        check_str=base.policy_or(
            base.SYSTEM_ADMIN,
            base.RULE_ADVSVC
        ),
        scope_types=['system', 'project'],
        description='Update ``mac_address`` attribute of a port',
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_port:mac_address',
            check_str=base.policy_or(
                base.RULE_ADMIN_ONLY,
                base.RULE_ADVSVC),
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_port:fixed_ips',
        check_str=base.policy_or(
            base.RULE_ADVSVC,
            base.RULE_NET_OWNER,
            base.SYSTEM_ADMIN,
            base.PROJECT_ADMIN
        ),
        scope_types=['system', 'project'],
        description='Specify ``fixed_ips`` information when updating a port',
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_port:fixed_ips',
            check_str=base.policy_or(
                base.RULE_ADVSVC,
                base.RULE_ADMIN_OR_NET_OWNER),
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_port:fixed_ips:ip_address',
        check_str=base.policy_or(
            base.RULE_ADVSVC,
            base.RULE_NET_OWNER,
            base.SYSTEM_ADMIN,
            base.PROJECT_ADMIN
        ),
        scope_types=['system', 'project'],
        description=(
            'Specify IP address in ``fixed_ips`` '
            'information when updating a port'
        ),
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_port:fixed_ips:ip_address',
            check_str=base.policy_or(
                base.RULE_ADVSVC,
                base.RULE_ADMIN_OR_NET_OWNER),
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_port:fixed_ips:subnet_id',
        check_str=base.policy_or(
            base.RULE_ADVSVC,
            base.RULE_NET_OWNER,
            base.SYSTEM_ADMIN,
            base.PROJECT_ADMIN,
            'rule:shared'
        ),
        scope_types=['system', 'project'],
        description=(
            'Specify subnet ID in ``fixed_ips`` '
            'information when updating a port'
        ),
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_port:fixed_ips:subnet_id',
            check_str=base.policy_or(
                base.RULE_ADVSVC,
                base.RULE_ADMIN_OR_NET_OWNER,
                'rule:shared'),
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_port:port_security_enabled',
        check_str=base.policy_or(
            base.RULE_ADVSVC,
            base.RULE_NET_OWNER,
            base.SYSTEM_ADMIN,
            base.PROJECT_ADMIN
        ),
        scope_types=['system', 'project'],
        description='Update ``port_security_enabled`` attribute of a port',
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_port:port_security_enabled',
            check_str=base.policy_or(
                base.RULE_ADVSVC,
                base.RULE_ADMIN_OR_NET_OWNER),
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_port:binding:host_id',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Update ``binding:host_id`` attribute of a port',
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_port:binding:host_id',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_port:binding:profile',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Update ``binding:profile`` attribute of a port',
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_port:binding:profile',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_port:binding:vnic_type',
        check_str=base.policy_or(
            base.SYSTEM_ADMIN_OR_PROJECT_MEMBER,
            base.RULE_ADVSVC
        ),
        scope_types=['system', 'project'],
        description='Update ``binding:vnic_type`` attribute of a port',
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_port:binding:vnic_type',
            check_str=base.policy_or(
                base.RULE_ADMIN_OR_OWNER,
                base.RULE_ADVSVC),
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_port:allowed_address_pairs',
        check_str=base.policy_or(
            base.SYSTEM_ADMIN,
            base.PROJECT_ADMIN,
            base.RULE_NET_OWNER),
        scope_types=['system', 'project'],
        description='Update ``allowed_address_pairs`` attribute of a port',
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_port:allowed_address_pairs',
            check_str=base.RULE_ADMIN_OR_NET_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_port:allowed_address_pairs:mac_address',
        check_str=base.policy_or(
            base.SYSTEM_ADMIN,
            base.PROJECT_ADMIN,
            base.RULE_NET_OWNER),
        scope_types=['system', 'project'],
        description=(
            'Update ``mac_address`` of ``allowed_address_pairs`` '
            'attribute of a port'
        ),
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_port:allowed_address_pairs:mac_address',
            check_str=base.RULE_ADMIN_OR_NET_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_port:allowed_address_pairs:ip_address',
        check_str=base.policy_or(
            base.SYSTEM_ADMIN,
            base.PROJECT_ADMIN,
            base.RULE_NET_OWNER),
        scope_types=['system', 'project'],
        description=(
            'Update ``ip_address`` of ``allowed_address_pairs`` '
            'attribute of a port'
        ),
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_port:allowed_address_pairs:ip_address',
            check_str=base.RULE_ADMIN_OR_NET_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
    policy.DocumentedRuleDefault(
        name='update_port:data_plane_status',
        check_str=base.policy_or(
            base.SYSTEM_ADMIN,
            'role:data_plane_integrator'),
        scope_types=['system', 'project'],
        description='Update ``data_plane_status`` attribute of a port',
        operations=ACTION_PUT,
        deprecated_rule=policy.DeprecatedRule(
            name='update_port:data_plane_status',
            check_str='rule:admin_or_data_plane_int',
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),

    policy.DocumentedRuleDefault(
        name='delete_port',
        check_str=base.policy_or(
            base.RULE_ADVSVC,
            base.SYSTEM_ADMIN_OR_PROJECT_MEMBER
        ),
        scope_types=['system', 'project'],
        description='Delete a port',
        operations=ACTION_DELETE,
        deprecated_rule=policy.DeprecatedRule(
            name='delete_port',
            check_str=base.policy_or(
                base.RULE_ADVSVC,
                'rule:admin_owner_or_network_owner'),
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since=versionutils.deprecated.WALLABY)
    ),
]


def list_rules():
    return rules
