# Copyright (c) 2012 OpenStack Foundation.
# All rights reserved.
#
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

import netaddr
from neutron_lib.api import converters
from neutron_lib.api import extensions as api_extensions
from neutron_lib.api import validators
from neutron_lib import constants as const
from neutron_lib.db import constants as db_const
from neutron_lib import exceptions
from neutron_lib.plugins import directory
from oslo_utils import netutils
import six

from neutron._i18n import _
from neutron.api import extensions
from neutron.api.v2 import base
from neutron.conf import quota
from neutron.extensions import standardattrdescription as stdattr_ext
from neutron.quota import resource_registry


# Security group Exceptions
class SecurityGroupInvalidPortRange(exceptions.InvalidInput):
    message = _("For TCP/UDP protocols, port_range_min must be "
                "<= port_range_max")


class SecurityGroupInvalidProtocolForPort(exceptions.InvalidInput):
    message = _("Ports cannot be specified for protocol %(protocol)s. "
                "Ports are only supported for %(valid_port_protocols)s.")


class SecurityGroupInvalidPortValue(exceptions.InvalidInput):
    message = _("Invalid value for port %(port)s")


class SecurityGroupInvalidIcmpValue(exceptions.InvalidInput):
    message = _("Invalid value for ICMP %(field)s (%(attr)s) "
                "%(value)s. It must be 0 to 255.")


class SecurityGroupEthertypeConflictWithProtocol(exceptions.InvalidInput):
    message = _("Invalid ethertype %(ethertype)s for protocol "
                "%(protocol)s.")


class SecurityGroupMissingIcmpType(exceptions.InvalidInput):
    message = _("ICMP code (port-range-max) %(value)s is provided"
                " but ICMP type (port-range-min) is missing.")


class SecurityGroupInUse(exceptions.InUse):
    message = _("Security Group %(id)s %(reason)s.")

    def __init__(self, **kwargs):
        if 'reason' not in kwargs:
            kwargs['reason'] = _("in use")
        super(SecurityGroupInUse, self).__init__(**kwargs)


class SecurityGroupCannotRemoveDefault(exceptions.InUse):
    message = _("Insufficient rights for removing default security group.")


class SecurityGroupCannotUpdateDefault(exceptions.InUse):
    message = _("Updating default security group not allowed.")


class SecurityGroupDefaultAlreadyExists(exceptions.InUse):
    message = _("Default security group already exists.")


class SecurityGroupRuleInvalidProtocol(exceptions.InvalidInput):
    message = _("Security group rule protocol %(protocol)s not supported. "
                "Only protocol values %(values)s and integer representations "
                "[0 to 255] are supported.")


class SecurityGroupRulesNotSingleTenant(exceptions.InvalidInput):
    message = _("Multiple tenant_ids in bulk security group rule create"
                " not allowed")


class SecurityGroupRemoteGroupAndRemoteIpPrefix(exceptions.InvalidInput):
    message = _("Only remote_ip_prefix or remote_group_id may "
                "be provided.")


class SecurityGroupProtocolRequiredWithPorts(exceptions.InvalidInput):
    message = _("Must also specify protocol if port range is given.")


class SecurityGroupNotSingleGroupRules(exceptions.InvalidInput):
    message = _("Only allowed to update rules for "
                "one security profile at a time")


class SecurityGroupNotFound(exceptions.NotFound):
    message = _("Security group %(id)s does not exist")


class SecurityGroupRuleNotFound(exceptions.NotFound):
    message = _("Security group rule %(id)s does not exist")


class DuplicateSecurityGroupRuleInPost(exceptions.InUse):
    message = _("Duplicate Security Group Rule in POST.")


class SecurityGroupRuleExists(exceptions.InUse):
    message = _("Security group rule already exists. Rule id is %(rule_id)s.")


class SecurityGroupRuleInUse(exceptions.InUse):
    message = _("Security Group Rule %(id)s %(reason)s.")

    def __init__(self, **kwargs):
        if 'reason' not in kwargs:
            kwargs['reason'] = _("in use")
        super(SecurityGroupRuleInUse, self).__init__(**kwargs)


class SecurityGroupRuleParameterConflict(exceptions.InvalidInput):
    message = _("Conflicting value ethertype %(ethertype)s for CIDR %(cidr)s")


class SecurityGroupConflict(exceptions.Conflict):
    message = _("Error %(reason)s while attempting the operation.")


class SecurityGroupRuleInvalidEtherType(exceptions.InvalidInput):
    message = _("Security group rule for ethertype '%(ethertype)s' not "
                "supported. Allowed values are %(values)s.")


def convert_protocol(value):
    if value is None:
        return
    try:
        val = int(value)
        if 0 <= val <= 255:
            # Set value of protocol number to string due to bug 1381379,
            # PostgreSQL fails when it tries to compare integer with string,
            # that exists in db.
            return str(value)
        raise SecurityGroupRuleInvalidProtocol(
            protocol=value, values=sg_supported_protocols)
    except (ValueError, TypeError):
        if value.lower() in sg_supported_protocols:
            return value.lower()
        raise SecurityGroupRuleInvalidProtocol(
            protocol=value, values=sg_supported_protocols)
    except AttributeError:
        raise SecurityGroupRuleInvalidProtocol(
            protocol=value, values=sg_supported_protocols)


def convert_ethertype_to_case_insensitive(value):
    if isinstance(value, six.string_types):
        for ethertype in sg_supported_ethertypes:
            if ethertype.lower() == value.lower():
                return ethertype
    raise SecurityGroupRuleInvalidEtherType(
        ethertype=value, values=sg_supported_ethertypes)


def convert_validate_port_value(port):
    if port is None:
        return port

    if netutils.is_valid_port(port):
        return int(port)
    else:
        raise SecurityGroupInvalidPortValue(port=port)


def convert_ip_prefix_to_cidr(ip_prefix):
    if not ip_prefix:
        return
    try:
        cidr = netaddr.IPNetwork(ip_prefix)
        return str(cidr)
    except (ValueError, TypeError, netaddr.AddrFormatError):
        raise exceptions.InvalidCIDR(input=ip_prefix)


def _validate_name_not_default(data, max_len=db_const.NAME_FIELD_SIZE):
    msg = validators.validate_string(data, max_len)
    if msg:
        return msg
    if data.lower() == "default":
        raise SecurityGroupDefaultAlreadyExists()


validators.add_validator('name_not_default', _validate_name_not_default)

sg_supported_protocols = ([None] + list(const.IP_PROTOCOL_MAP.keys()))
sg_supported_ethertypes = ['IPv4', 'IPv6']
SECURITYGROUPS = 'security_groups'
SECURITYGROUPRULES = 'security_group_rules'

# Attribute Map
RESOURCE_ATTRIBUTE_MAP = {
    SECURITYGROUPS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'is_filter': True,
               'is_sort_key': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'is_visible': True, 'default': '', 'is_filter': True,
                 'is_sort_key': True,
                 'validate': {
                     'type:name_not_default': db_const.NAME_FIELD_SIZE}},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_sort_key': True,
                      'validate': {
                          'type:string': db_const.PROJECT_ID_FIELD_SIZE},
                      'is_visible': True, 'is_filter': True},
        const.SHARED: {'allow_post': False,
                       'allow_put': False,
                       'convert_to': converters.convert_to_boolean,
                       'is_visible': True,
                       'is_filter': True,
                       'is_sort_key': True,
                       'enforce_policy': True},
        SECURITYGROUPRULES: {'allow_post': False, 'allow_put': False,
                             'is_visible': True},
    },
    SECURITYGROUPRULES: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'is_filter': True,
               'is_sort_key': True,
               'primary_key': True},
        'security_group_id': {'allow_post': True, 'allow_put': False,
                              'is_visible': True, 'required_by_policy': True,
                              'is_sort_key': True, 'is_filter': True},
        'remote_group_id': {'allow_post': True, 'allow_put': False,
                            'default': None, 'is_visible': True,
                            'is_sort_key': True, 'is_filter': True},
        'direction': {'allow_post': True, 'allow_put': False,
                      'is_visible': True, 'is_filter': True,
                      'is_sort_key': True,
                      'validate': {'type:values': ['ingress', 'egress']}},
        'protocol': {'allow_post': True, 'allow_put': False,
                     'is_visible': True, 'default': None,
                     'is_sort_key': True, 'is_filter': True,
                     'convert_to': convert_protocol},
        'port_range_min': {'allow_post': True, 'allow_put': False,
                           'convert_to': convert_validate_port_value,
                           'default': None, 'is_visible': True,
                           'is_sort_key': True, 'is_filter': True},
        'port_range_max': {'allow_post': True, 'allow_put': False,
                           'convert_to': convert_validate_port_value,
                           'default': None, 'is_visible': True,
                           'is_sort_key': True, 'is_filter': True},
        'ethertype': {'allow_post': True, 'allow_put': False,
                      'is_visible': True, 'default': 'IPv4',
                      'is_filter': True, 'is_sort_key': True,
                      'convert_to': convert_ethertype_to_case_insensitive,
                      'validate': {'type:values': sg_supported_ethertypes}},
        'remote_ip_prefix': {'allow_post': True, 'allow_put': False,
                             'default': None, 'is_visible': True,
                             'is_sort_key': True, 'is_filter': True,
                             'convert_to': convert_ip_prefix_to_cidr},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_sort_key': True,
                      'validate': {
                          'type:string': db_const.PROJECT_ID_FIELD_SIZE},
                      'is_visible': True, 'is_filter': True},
    }
}


EXTENDED_ATTRIBUTES_2_0 = {
    'ports': {SECURITYGROUPS: {'allow_post': True,
                               'allow_put': True,
                               'is_visible': True,
                               'is_filter': True,
                               'convert_to':
                                   converters.convert_none_to_empty_list,
                               'validate': {'type:uuid_list': None},
                               'enforce_policy': True,
                               'default': const.ATTR_NOT_SPECIFIED}}}

# Register the configuration options
quota.register_quota_opts(quota.security_group_quota_opts)


class Securitygroup(api_extensions.ExtensionDescriptor):
    """Security group extension."""

    @classmethod
    def get_name(cls):
        return "security-group"

    @classmethod
    def get_alias(cls):
        return "security-group"

    @classmethod
    def get_description(cls):
        return "The security groups extension."

    @classmethod
    def get_updated(cls):
        return "2012-10-05T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        exts = []
        plugin = directory.get_plugin()
        for resource_name in ['security_group', 'security_group_rule']:
            collection_name = resource_name.replace('_', '-') + "s"
            params = RESOURCE_ATTRIBUTE_MAP.get(resource_name + "s", dict())
            resource_registry.register_resource_by_name(resource_name)
            controller = base.create_resource(collection_name,
                                              resource_name,
                                              plugin, params, allow_bulk=True,
                                              allow_pagination=True,
                                              allow_sorting=True)

            ex = extensions.ResourceExtension(collection_name,
                                              controller,
                                              attr_map=params)
            exts.append(ex)

        return exts

    def update_attributes_map(self, attributes):
        super(Securitygroup, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return dict(list(EXTENDED_ATTRIBUTES_2_0.items()) +
                        list(RESOURCE_ATTRIBUTE_MAP.items()))
        else:
            return {}

    def get_required_extensions(self):
        return [stdattr_ext.Standardattrdescription.get_alias()]


@six.add_metaclass(abc.ABCMeta)
class SecurityGroupPluginBase(object):

    @abc.abstractmethod
    def create_security_group(self, context, security_group):
        pass

    @abc.abstractmethod
    def update_security_group(self, context, id, security_group):
        pass

    @abc.abstractmethod
    def delete_security_group(self, context, id):
        pass

    @abc.abstractmethod
    def get_security_groups(self, context, filters=None, fields=None,
                            sorts=None, limit=None, marker=None,
                            page_reverse=False):
        pass

    @abc.abstractmethod
    def get_security_group(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_security_group_rule(self, context, security_group_rule):
        pass

    @abc.abstractmethod
    def delete_security_group_rule(self, context, id):
        pass

    @abc.abstractmethod
    def get_security_group_rules(self, context, filters=None, fields=None,
                                 sorts=None, limit=None, marker=None,
                                 page_reverse=False):
        pass

    @abc.abstractmethod
    def get_security_group_rule(self, context, id, fields=None):
        pass
