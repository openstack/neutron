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

from oslo_config import cfg
import six

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import base
from neutron.common import constants as const
from neutron.common import exceptions as nexception
from neutron import manager
from neutron.openstack.common import uuidutils
from neutron import quota


# Security group Exceptions
class SecurityGroupInvalidPortRange(nexception.InvalidInput):
    message = _("For TCP/UDP protocols, port_range_min must be "
                "<= port_range_max")


class SecurityGroupInvalidPortValue(nexception.InvalidInput):
    message = _("Invalid value for port %(port)s")


class SecurityGroupInvalidIcmpValue(nexception.InvalidInput):
    message = _("Invalid value for ICMP %(field)s (%(attr)s) "
                "%(value)s. It must be 0 to 255.")


class SecurityGroupMissingIcmpType(nexception.InvalidInput):
    message = _("ICMP code (port-range-max) %(value)s is provided"
                " but ICMP type (port-range-min) is missing.")


class SecurityGroupInUse(nexception.InUse):
    message = _("Security Group %(id)s %(reason)s.")

    def __init__(self, **kwargs):
        if 'reason' not in kwargs:
            kwargs['reason'] = _("in use")
        super(SecurityGroupInUse, self).__init__(**kwargs)


class SecurityGroupCannotRemoveDefault(nexception.InUse):
    message = _("Insufficient rights for removing default security group.")


class SecurityGroupCannotUpdateDefault(nexception.InUse):
    message = _("Updating default security group not allowed.")


class SecurityGroupDefaultAlreadyExists(nexception.InUse):
    message = _("Default security group already exists.")


class SecurityGroupRuleInvalidProtocol(nexception.InvalidInput):
    message = _("Security group rule protocol %(protocol)s not supported. "
                "Only protocol values %(values)s and their integer "
                "representation (0 to 255) are supported.")


class SecurityGroupRulesNotSingleTenant(nexception.InvalidInput):
    message = _("Multiple tenant_ids in bulk security group rule create"
                " not allowed")


class SecurityGroupRemoteGroupAndRemoteIpPrefix(nexception.InvalidInput):
    message = _("Only remote_ip_prefix or remote_group_id may "
                "be provided.")


class SecurityGroupProtocolRequiredWithPorts(nexception.InvalidInput):
    message = _("Must also specifiy protocol if port range is given.")


class SecurityGroupNotSingleGroupRules(nexception.InvalidInput):
    message = _("Only allowed to update rules for "
                "one security profile at a time")


class SecurityGroupNotFound(nexception.NotFound):
    message = _("Security group %(id)s does not exist")


class SecurityGroupRuleNotFound(nexception.NotFound):
    message = _("Security group rule %(id)s does not exist")


class DuplicateSecurityGroupRuleInPost(nexception.InUse):
    message = _("Duplicate Security Group Rule in POST.")


class SecurityGroupRuleExists(nexception.InUse):
    message = _("Security group rule already exists. Rule id is %(id)s.")


class SecurityGroupRuleInUse(nexception.InUse):
    message = _("Security Group Rule %(id)s %(reason)s.")

    def __init__(self, **kwargs):
        if 'reason' not in kwargs:
            kwargs['reason'] = _("in use")
        super(SecurityGroupRuleInUse, self).__init__(**kwargs)


class SecurityGroupRuleParameterConflict(nexception.InvalidInput):
    message = _("Conflicting value ethertype %(ethertype)s for CIDR %(cidr)s")


class SecurityGroupConflict(nexception.Conflict):
    message = _("Error %(reason)s while attempting the operation.")


def convert_protocol(value):
    if value is None:
        return
    try:
        val = int(value)
        if val >= 0 and val <= 255:
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
    if isinstance(value, basestring):
        for ethertype in sg_supported_ethertypes:
            if ethertype.lower() == value.lower():
                return ethertype


def convert_validate_port_value(port):
    if port is None:
        return port
    try:
        val = int(port)
    except (ValueError, TypeError):
        raise SecurityGroupInvalidPortValue(port=port)

    if val >= 0 and val <= 65535:
        return val
    else:
        raise SecurityGroupInvalidPortValue(port=port)


def convert_to_uuid_list_or_none(value_list):
    if value_list is None:
        return
    for sg_id in value_list:
        if not uuidutils.is_uuid_like(sg_id):
            msg = _("'%s' is not an integer or uuid") % sg_id
            raise nexception.InvalidInput(error_message=msg)
    return value_list


def convert_ip_prefix_to_cidr(ip_prefix):
    if not ip_prefix:
        return
    try:
        cidr = netaddr.IPNetwork(ip_prefix)
        return str(cidr)
    except (ValueError, TypeError, netaddr.AddrFormatError):
        raise nexception.InvalidCIDR(input=ip_prefix)


def _validate_name_not_default(data, valid_values=None):
    if data.lower() == "default":
        raise SecurityGroupDefaultAlreadyExists()


attr.validators['type:name_not_default'] = _validate_name_not_default

sg_supported_protocols = [None, const.PROTO_NAME_TCP,
                          const.PROTO_NAME_UDP, const.PROTO_NAME_ICMP]
sg_supported_ethertypes = ['IPv4', 'IPv6']

# Attribute Map
RESOURCE_ATTRIBUTE_MAP = {
    'security_groups': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'is_visible': True, 'default': '',
                 'validate': {'type:name_not_default': attr.NAME_MAX_LEN}},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': attr.DESCRIPTION_MAX_LEN},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
        'security_group_rules': {'allow_post': False, 'allow_put': False,
                                 'is_visible': True},
    },
    'security_group_rules': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'security_group_id': {'allow_post': True, 'allow_put': False,
                              'is_visible': True, 'required_by_policy': True},
        'remote_group_id': {'allow_post': True, 'allow_put': False,
                            'default': None, 'is_visible': True},
        'direction': {'allow_post': True, 'allow_put': True,
                      'is_visible': True,
                      'validate': {'type:values': ['ingress', 'egress']}},
        'protocol': {'allow_post': True, 'allow_put': False,
                     'is_visible': True, 'default': None,
                     'convert_to': convert_protocol},
        'port_range_min': {'allow_post': True, 'allow_put': False,
                           'convert_to': convert_validate_port_value,
                           'default': None, 'is_visible': True},
        'port_range_max': {'allow_post': True, 'allow_put': False,
                           'convert_to': convert_validate_port_value,
                           'default': None, 'is_visible': True},
        'ethertype': {'allow_post': True, 'allow_put': False,
                      'is_visible': True, 'default': 'IPv4',
                      'convert_to': convert_ethertype_to_case_insensitive,
                      'validate': {'type:values': sg_supported_ethertypes}},
        'remote_ip_prefix': {'allow_post': True, 'allow_put': False,
                             'default': None, 'is_visible': True,
                             'convert_to': convert_ip_prefix_to_cidr},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
    }
}


SECURITYGROUPS = 'security_groups'
EXTENDED_ATTRIBUTES_2_0 = {
    'ports': {SECURITYGROUPS: {'allow_post': True,
                               'allow_put': True,
                               'is_visible': True,
                               'convert_to': convert_to_uuid_list_or_none,
                               'default': attr.ATTR_NOT_SPECIFIED}}}
security_group_quota_opts = [
    cfg.IntOpt('quota_security_group',
               default=10,
               help=_('Number of security groups allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_security_group_rule',
               default=100,
               help=_('Number of security rules allowed per tenant. '
                      'A negative value means unlimited.')),
]
cfg.CONF.register_opts(security_group_quota_opts, 'QUOTAS')


class Securitygroup(extensions.ExtensionDescriptor):
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
    def get_namespace(cls):
        # todo
        return "http://docs.openstack.org/ext/securitygroups/api/v2.0"

    @classmethod
    def get_updated(cls):
        return "2012-10-05T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        my_plurals = [(key, key[:-1]) for key in RESOURCE_ATTRIBUTE_MAP.keys()]
        attr.PLURALS.update(dict(my_plurals))
        exts = []
        plugin = manager.NeutronManager.get_plugin()
        for resource_name in ['security_group', 'security_group_rule']:
            collection_name = resource_name.replace('_', '-') + "s"
            params = RESOURCE_ATTRIBUTE_MAP.get(resource_name + "s", dict())
            quota.QUOTAS.register_resource_by_name(resource_name)
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

    def get_extended_resources(self, version):
        if version == "2.0":
            return dict(EXTENDED_ATTRIBUTES_2_0.items() +
                        RESOURCE_ATTRIBUTE_MAP.items())
        else:
            return {}


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
