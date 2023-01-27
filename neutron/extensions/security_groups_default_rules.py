#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from neutron_lib.api import converters
from neutron_lib.api import extensions as api_extensions
from neutron_lib.plugins import directory

from neutron.api import extensions
from neutron.api.v2 import base
from neutron.extensions import securitygroup

# TODO(slaweq): rehome API definition to neutron-lib together with
# securitygroup API definition

ALIAS = 'security-groups-default-rules'
IS_SHIM_EXTENSION = False
IS_STANDARD_ATTR_EXTENSION = False
NAME = 'Default rules for security groups'
DESCRIPTION = (
    'Configure set of security group rules used as default rules '
    'for every new security group')
UPDATED_TIMESTAMP = '2022-12-19T10:00:00-00:00'

RESOURCE_NAME = 'default_security_group_rule'
COLLECTION_NAME = 'default_security_group_rules'

RESOURCE_ATTRIBUTE_MAP = {
    COLLECTION_NAME: {
        'id': {
            'allow_post': False, 'allow_put': False,
            'validate': {'type:uuid': None},
            'is_visible': True,
            'is_filter': True,
            'is_sort_key': True,
            'primary_key': True},
        'remote_group_id': {
            'allow_post': True, 'allow_put': False,
            'default': None, 'is_visible': True,
            'is_sort_key': True, 'is_filter': True},
        'direction': {
            'allow_post': True, 'allow_put': False,
            'is_visible': True, 'is_filter': True,
            'is_sort_key': True,
            'validate': {'type:values': ['ingress', 'egress']}},
        'protocol': {
            'allow_post': True, 'allow_put': False,
            'is_visible': True, 'default': None,
            'is_sort_key': True, 'is_filter': True,
            'convert_to': securitygroup.convert_protocol},
        'port_range_min': {
            'allow_post': True, 'allow_put': False,
            'convert_to': securitygroup.convert_validate_port_value,
            'default': None, 'is_visible': True,
            'is_sort_key': True, 'is_filter': True},
        'port_range_max': {
            'allow_post': True, 'allow_put': False,
            'convert_to': securitygroup.convert_validate_port_value,
            'default': None, 'is_visible': True,
            'is_sort_key': True, 'is_filter': True},
        'ethertype': {
            'allow_post': True, 'allow_put': False,
            'is_visible': True, 'default': 'IPv4',
            'is_filter': True, 'is_sort_key': True,
            'convert_to': securitygroup.convert_ethertype_to_case_insensitive,
            'validate': {
                'type:values': securitygroup.sg_supported_ethertypes}},
        'remote_ip_prefix': {
            'allow_post': True, 'allow_put': False,
            'default': None, 'is_visible': True,
            'is_sort_key': True, 'is_filter': True,
            'convert_to': securitygroup.convert_ip_prefix_to_cidr},
        'used_in_default_sg': {
            'allow_post': True, 'allow_put': False,
            'convert_to': converters.convert_to_boolean,
            'is_visible': True, 'is_filter': True},
    }
}

SUB_RESOURCE_ATTRIBUTE_MAP = None

ACTION_MAP = {
}

ACTION_STATUS = {
}

REQUIRED_EXTENSIONS = [
    'security-group'
]

OPTIONAL_EXTENSIONS = [
]


class Security_groups_default_rules(api_extensions.ExtensionDescriptor):
    """Security group default rules template extension."""

    @classmethod
    def get_name(cls):
        return NAME

    @classmethod
    def get_alias(cls):
        return ALIAS

    @classmethod
    def get_description(cls):
        return DESCRIPTION

    @classmethod
    def get_updated(cls):
        return UPDATED_TIMESTAMP

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plugin = directory.get_plugin()
        params = RESOURCE_ATTRIBUTE_MAP.get(COLLECTION_NAME)
        controller = base.create_resource(COLLECTION_NAME,
                                          RESOURCE_NAME,
                                          plugin, params)

        ex = extensions.ResourceExtension(COLLECTION_NAME,
                                          controller)

        return [ex]
