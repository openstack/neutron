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

import abc

from neutron_lib.api import converters
from neutron_lib.api import extensions as api_extensions
from neutron_lib.db import constants as db_const
from neutron_lib import exceptions
from neutron_lib.plugins import directory

from neutron._i18n import _
from neutron.api import extensions
from neutron.api.v2 import base
from neutron.extensions import securitygroup
from neutron.extensions import standardattrdescription as stdattr_ext


PARENT_SG = 'PARENT'


class DefaultSecurityGroupRuleNotFound(exceptions.NotFound):
    message = _("Default Security Group rule %(id)s does not exist")


class DefaultSecurityGroupRuleExists(exceptions.InUse):
    message = _("Default Security group rule already exists. "
                "Rule id is %(rule_id)s.")


class DuplicateDefaultSgRuleInPost(exceptions.InUse):
    message = _("Duplicate Default Security Group Rule in POST.")


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
        'tenant_id': {
            'allow_post': True, 'allow_put': False,
            'required_by_policy': True,
            'is_sort_key': False,
            'validate': {'type:string': db_const.PROJECT_ID_FIELD_SIZE},
            'is_visible': False, 'is_filter': False},
        'description': {
            'allow_post': True, 'allow_put': False, 'default': '',
            'validate': {'type:string': db_const.LONG_DESCRIPTION_FIELD_SIZE},
            'is_filter': True, 'is_sort_key': False, 'is_visible': True},
        'remote_group_id': {
            'allow_post': True, 'allow_put': False,
            'default': None, 'is_visible': True,
            'is_sort_key': True, 'is_filter': True},
        'remote_address_group_id': {
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
        'used_in_non_default_sg': {
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
    'security-group', stdattr_ext.Standardattrdescription.get_alias()
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
        collection_name = COLLECTION_NAME.replace('_', '-')
        params = RESOURCE_ATTRIBUTE_MAP.get(COLLECTION_NAME, dict())
        controller = base.create_resource(COLLECTION_NAME,
                                          RESOURCE_NAME,
                                          plugin, params,
                                          allow_pagination=True,
                                          allow_sorting=True)

        ex = extensions.ResourceExtension(collection_name, controller,
                                          attr_map=params)

        return [ex]


class SecurityGroupDefaultRulesPluginBase(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def create_default_security_group_rule(self, context, sg_rule_template):
        pass

    @abc.abstractmethod
    def delete_default_security_group_rule(self, context, sg_rule_template_id):
        pass

    @abc.abstractmethod
    def get_default_security_group_rules(self, context, filters=None,
                                         fields=None, sorts=None, limit=None,
                                         marker=None, page_reverse=False):
        pass

    @abc.abstractmethod
    def get_default_security_group_rule(self, context, sg_rule_template_id,
                                        fields=None):
        pass
