# Copyright (c) 2012 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from abc import abstractmethod

from quantum.api.v2 import attributes as attr
from quantum.api.v2 import base
from quantum.common import exceptions as qexception
from quantum.extensions import extensions
from quantum import manager
from quantum.openstack.common import cfg
from quantum import quota


# Security group Exceptions
class SecurityGroupAlreadyExists(qexception.InUse):
    # This can only happen if the external_id database is cleared
    message = _("Security group %(name)s id %(external_id)s already exists")


class SecurityGroupInvalidProtocolType(qexception.InvalidInput):
    message = _("Invalid protocol type %(value)s")


class SecurityGroupInvalidEtherType(qexception.InvalidInput):
    message = _("Invalid/Unsupported ethertype %(value)s")


class SecurityGroupInvalidPortRange(qexception.InvalidInput):
    message = _("For TCP/UDP protocols, port_range_min must be "
                "<= port_range_max")


class SecurityGroupInvalidPortValue(qexception.InvalidInput):
    message = _("Invalid value for port %(port)s")


class SecurityGroupInUse(qexception.InUse):
    message = _("Security Group %(id)s in use.")


class SecurityGroupCannotRemoveDefault(qexception.InUse):
    message = _("Removing default security group not allowed.")


class SecurityGroupDefaultAlreadyExists(qexception.InUse):
    message = _("Default security group already exists.")


class SecurityGroupRuleInvalidProtocol(qexception.InUse):
    message = _("Security group rule protocol %(protocol)s not supported "
                "only protocol values %(values)s supported.")


class SecurityGroupRulesNotSingleTenant(qexception.InvalidInput):
    message = _("Multiple tenant_ids in bulk security group rule create"
                " not allowed")


class SecurityGroupSourceGroupAndIpPrefix(qexception.InvalidInput):
    message = _("Only source_ip_prefix or source_group_id may "
                "be provided.")


class SecurityGroupProtocolRequiredWithPorts(qexception.InvalidInput):
    message = _("Must also specifiy protocol if port range is given.")


class SecurityGroupNotSingleGroupRules(qexception.InvalidInput):
    message = _("Only allowed to update rules for "
                "one security profile at a time")


class SecurityGroupSourceGroupNotFound(qexception.NotFound):
    message = _("source group id %(id)s does not exist")


class SecurityGroupNotFound(qexception.NotFound):
    message = _("Security group %(id)s does not exist")


class SecurityGroupRuleNotFound(qexception.NotFound):
    message = _("Security group rule %(id)s does not exist")


class DuplicateSecurityGroupRuleInPost(qexception.InUse):
    message = _("Duplicate Security Group Rule in POST.")


class SecurityGroupRuleExists(qexception.InUse):
    message = _("Security group rule exists %(rule)s")


class SecurityGroupProxyMode(qexception.InUse):
    message = _("Did not recieve external id and in proxy mode")


class SecurityGroupNotProxyMode(qexception.InUse):
    message = _("Recieve external id and not in proxy mode")


class SecurityGroupProxyModeNotAdmin(qexception.InvalidExtenstionEnv):
    message = _("In Proxy Mode and not from admin")


class SecurityGroupInvalidExternalID(qexception.InvalidInput):
    message = _("external_id wrong type %(data)s")


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


def _validate_name_not_default(data, valid_values=None):
    if not cfg.CONF.SECURITYGROUP.proxy_mode and data == "default":
        raise SecurityGroupDefaultAlreadyExists()


def _validate_external_id_and_mode(external_id, valid_values=None):
    if not cfg.CONF.SECURITYGROUP.proxy_mode and not external_id:
        return
    elif not cfg.CONF.SECURITYGROUP.proxy_mode and external_id:
        raise SecurityGroupNotProxyMode()
    try:
        int(external_id)
    except (ValueError, TypeError):
        raise SecurityGroupInvalidExternalID(data=external_id)
    if cfg.CONF.SECURITYGROUP.proxy_mode and not external_id:
        raise SecurityGroupProxyMode()

attr.validators['type:name_not_default'] = _validate_name_not_default
attr.validators['type:external_id_and_mode'] = _validate_external_id_and_mode

# Attribute Map
RESOURCE_ATTRIBUTE_MAP = {
    'security_groups': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:regex': attr.UUID_PATTERN},
               'is_visible': True},
        'name': {'allow_post': True, 'allow_put': False,
                 'is_visible': True, 'default': '',
                 'validate': {'type:name_not_default': None}},
        'description': {'allow_post': True, 'allow_put': False,
                        'is_visible': True, 'default': ''},
        'external_id': {'allow_post': True, 'allow_put': False,
                        'is_visible': True, 'default': None,
                        'validate': {'type:external_id_and_mode': None}},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
    },
    'security_group_rules': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:regex': attr.UUID_PATTERN},
               'is_visible': True},
        # external_id can be used to be backwards compatible with nova
        'external_id': {'allow_post': True, 'allow_put': False,
                        'is_visible': True, 'default': None,
                        'validate': {'type:external_id_and_mode': None}},
        'security_group_id': {'allow_post': True, 'allow_put': False,
                              'is_visible': True, 'required_by_policy': True},
        'source_group_id': {'allow_post': True, 'allow_put': False,
                            'default': None, 'is_visible': True},
        'direction': {'allow_post': True, 'allow_put': True,
                      'is_visible': True,
                      'validate': {'type:values': ['ingress', 'egress']}},
        'protocol': {'allow_post': True, 'allow_put': False,
                     'is_visible': True, 'default': None},
        'port_range_min': {'allow_post': True, 'allow_put': False,
                           'convert_to': convert_validate_port_value,
                           'default': None, 'is_visible': True},
        'port_range_max': {'allow_post': True, 'allow_put': False,
                           'convert_to': convert_validate_port_value,
                           'default': None, 'is_visible': True},
        'ethertype': {'allow_post': True, 'allow_put': False,
                      'is_visible': True, 'default': 'IPv4'},
        'source_ip_prefix': {'allow_post': True, 'allow_put': False,
                             'default': None, 'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
    }
}


SECURITYGROUP = 'security_groups'
EXTENDED_ATTRIBUTES_2_0 = {
    'ports': {SECURITYGROUP: {'allow_post': True,
                              'allow_put': True,
                              'is_visible': True,
                              'default': None}}}
security_group_quota_opts = [
    cfg.IntOpt('quota_security_group',
               default=10,
               help='number of security groups allowed per tenant,'
                    '-1 for unlimited'),
    cfg.IntOpt('quota_security_group_rule',
               default=100,
               help='number of security rules allowed per tenant, '
                    '-1 for unlimited'),
]
cfg.CONF.register_opts(security_group_quota_opts, 'QUOTAS')

security_group_opts = [
    cfg.StrOpt('proxy_mode', default=False)
]
cfg.CONF.register_opts(security_group_opts, 'SECURITYGROUP')


class Securitygroup(object):
    """ Security group extension"""

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
        """ Returns Ext Resources """
        exts = []
        plugin = manager.QuantumManager.get_plugin()
        for resource_name in ['security_group', 'security_group_rule']:
            collection_name = resource_name.replace('_', '-') + "s"
            params = RESOURCE_ATTRIBUTE_MAP.get(resource_name + "s", dict())
            quota.QUOTAS.register_resource_by_name(resource_name)
            controller = base.create_resource(collection_name,
                                              resource_name,
                                              plugin, params, allow_bulk=True)

            ex = extensions.ResourceExtension(collection_name,
                                              controller)
            exts.append(ex)

        return exts

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}


class SecurityGroupPluginBase(object):
    @abstractmethod
    def create_security_group(self, context, security_group):
        pass

    @abstractmethod
    def delete_security_group(self, context, security_group):
        pass

    @abstractmethod
    def update_security_group(self, context, security_group):
        pass

    @abstractmethod
    def get_security_groups(self, context, filters=None, fields=None):
        pass

    @abstractmethod
    def get_security_group(self, context, id, fields=None):
        pass

    @abstractmethod
    def create_security_group_rule(self, context, security_group_rule):
        pass

    @abstractmethod
    def delete_security_group_rule(self, context, sgrid):
        pass

    @abstractmethod
    def get_security_group_rules(self, context, filters=None, fields=None):
        pass

    @abstractmethod
    def get_security_group_rule(self, context, id, fields=None):
        pass
