# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Big Switch Networks, Inc.
# All Rights Reserved.
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
#
# @author: Sumit Naiksatam, sumitnaiksatam@gmail.com, Big Switch Networks, Inc.

import abc

from oslo.config import cfg

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import base
from neutron.common import exceptions as qexception
from neutron import manager
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants
from neutron.services.service_base import ServicePluginBase


LOG = logging.getLogger(__name__)


# Firewall Exceptions
class FirewallNotFound(qexception.NotFound):
    message = _("Firewall %(firewall_id)s could not be found.")


class FirewallInUse(qexception.InUse):
    message = _("Firewall %(firewall_id)s is still active.")


class FirewallInPendingState(qexception.Conflict):
    message = _("Operation cannot be performed since associated Firewall "
                "%(firewall_id)s is in %(pending_state)s.")


class FirewallPolicyNotFound(qexception.NotFound):
    message = _("Firewall Policy %(firewall_policy_id)s could not be found.")


class FirewallPolicyInUse(qexception.InUse):
    message = _("Firewall Policy %(firewall_policy_id)s is being used.")


class FirewallRuleNotFound(qexception.NotFound):
    message = _("Firewall Rule %(firewall_rule_id)s could not be found.")


class FirewallRuleInUse(qexception.InUse):
    message = _("Firewall Rule %(firewall_rule_id)s is being used.")


class FirewallRuleNotAssociatedWithPolicy(qexception.InvalidInput):
    message = _("Firewall Rule %(firewall_rule_id)s is not associated "
                " with Firewall Policy %(firewall_policy_id)s.")


class FirewallRuleInvalidProtocol(qexception.InvalidInput):
    message = _("Firewall Rule protocol %(protocol)s is not supported. "
                "Only protocol values %(values)s and their integer "
                "representation (0 to 255) are supported.")


class FirewallRuleInvalidAction(qexception.InvalidInput):
    message = _("Firewall rule action %(action)s is not supported. "
                "Only action values %(values)s are supported.")


class FirewallInvalidPortValue(qexception.InvalidInput):
    message = _("Invalid value for port %(port)s.")


class FirewallRuleInfoMissing(qexception.InvalidInput):
    message = _("Missing rule info argument for insert/remove "
                "rule operation.")


fw_valid_protocol_values = [None, constants.TCP, constants.UDP, constants.ICMP]
fw_valid_action_values = [constants.FWAAS_ALLOW, constants.FWAAS_DENY]


def convert_protocol(value):
    if value is None:
        return
    if value.isdigit():
        val = int(value)
        if 0 <= val <= 255:
            return val
        else:
            raise FirewallRuleInvalidProtocol(protocol=value,
                                              values=
                                              fw_valid_protocol_values)
    elif value.lower() in fw_valid_protocol_values:
        return value.lower()
    else:
        raise FirewallRuleInvalidProtocol(protocol=value,
                                          values=
                                          fw_valid_protocol_values)


def convert_action_to_case_insensitive(value):
    if value is None:
        return
    else:
        return value.lower()


def convert_port_to_string(value):
    if value is None:
        return
    else:
        return str(value)


def _validate_port_range(data, key_specs=None):
    if data is None:
        return
    data = str(data)
    ports = data.split(':')
    for p in ports:
        try:
            val = int(p)
        except (ValueError, TypeError):
            msg = _("Port '%s' is not a valid number") % p
            LOG.debug(msg)
            return msg
        if val <= 0 or val > 65535:
            msg = _("Invalid port '%s'") % p
            LOG.debug(msg)
            return msg


def _validate_ip_or_subnet_or_none(data, valid_values=None):
    if data is None:
        return None
    msg_ip = attr._validate_ip_address(data, valid_values)
    if not msg_ip:
        return
    msg_subnet = attr._validate_subnet(data, valid_values)
    if not msg_subnet:
        return
    return _("%(msg_ip)s and %(msg_subnet)s") % {'msg_ip': msg_ip,
                                                 'msg_subnet': msg_subnet}


attr.validators['type:port_range'] = _validate_port_range
attr.validators['type:ip_or_subnet_or_none'] = _validate_ip_or_subnet_or_none


RESOURCE_ATTRIBUTE_MAP = {
    'firewall_rules': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True, 'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': True, 'default': ''},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'firewall_policy_id': {'allow_post': False, 'allow_put': False,
                               'validate': {'type:uuid_or_none': None},
                               'is_visible': True},
        'shared': {'allow_post': True, 'allow_put': True,
                   'default': False, 'convert_to': attr.convert_to_boolean,
                   'is_visible': True, 'required_by_policy': True,
                   'enforce_policy': True},
        'protocol': {'allow_post': True, 'allow_put': True,
                     'is_visible': True, 'default': None,
                     'convert_to': convert_protocol,
                     'validate': {'type:values': fw_valid_protocol_values}},
        'ip_version': {'allow_post': True, 'allow_put': True,
                       'default': 4, 'convert_to': attr.convert_to_int,
                       'validate': {'type:values': [4, 6]},
                       'is_visible': True},
        'source_ip_address': {'allow_post': True, 'allow_put': True,
                              'validate': {'type:ip_or_subnet_or_none': None},
                              'is_visible': True, 'default': None},
        'destination_ip_address': {'allow_post': True, 'allow_put': True,
                                   'validate': {'type:ip_or_subnet_or_none':
                                                None},
                                   'is_visible': True, 'default': None},
        'source_port': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:port_range': None},
                        'convert_to': convert_port_to_string,
                        'default': None, 'is_visible': True},
        'destination_port': {'allow_post': True, 'allow_put': True,
                             'validate': {'type:port_range': None},
                             'convert_to': convert_port_to_string,
                             'default': None, 'is_visible': True},
        'position': {'allow_post': False, 'allow_put': False,
                     'default': None, 'is_visible': True},
        'action': {'allow_post': True, 'allow_put': True,
                   'convert_to': convert_action_to_case_insensitive,
                   'validate': {'type:values': fw_valid_action_values},
                   'is_visible': True, 'default': 'deny'},
        'enabled': {'allow_post': True, 'allow_put': True,
                    'default': True, 'convert_to': attr.convert_to_boolean,
                    'is_visible': True},
    },
    'firewall_policies': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': True, 'default': ''},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'shared': {'allow_post': True, 'allow_put': True,
                   'default': False, 'convert_to': attr.convert_to_boolean,
                   'is_visible': True, 'required_by_policy': True,
                   'enforce_policy': True},
        'firewall_rules': {'allow_post': True, 'allow_put': True,
                           'convert_to': attr.convert_none_to_empty_list,
                           'default': None, 'is_visible': True},
        'audited': {'allow_post': True, 'allow_put': True,
                    'default': False, 'convert_to': attr.convert_to_boolean,
                    'is_visible': True},
    },
    'firewalls': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': True, 'default': ''},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'admin_state_up': {'allow_post': True, 'allow_put': True,
                           'default': True,
                           'convert_to': attr.convert_to_boolean,
                           'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'shared': {'allow_post': True, 'allow_put': True,
                   'default': False, 'convert_to': attr.convert_to_boolean,
                   'is_visible': False, 'required_by_policy': True,
                   'enforce_policy': True},
        'firewall_policy_id': {'allow_post': True, 'allow_put': True,
                               'validate': {'type:uuid_or_none': None},
                               'is_visible': True},
    },
}

firewall_quota_opts = [
    cfg.IntOpt('quota_firewall',
               default=1,
               help=_('Number of firewalls allowed per tenant, -1 for '
                      'unlimited')),
    cfg.IntOpt('quota_firewall_policy',
               default=1,
               help=_('Number of firewall policies allowed per tenant, -1 '
                      'for unlimited')),
    cfg.IntOpt('quota_firewall_rule',
               default=-1,
               help=_('Number of firewall rules allowed per tenant, -1 '
                      'for unlimited')),
]
cfg.CONF.register_opts(firewall_quota_opts, 'QUOTAS')


class Firewall(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Firewall service"

    @classmethod
    def get_alias(cls):
        return "fwaas"

    @classmethod
    def get_description(cls):
        return "Extension for Firewall service"

    @classmethod
    def get_namespace(cls):
        return "http://wiki.openstack.org/Neutron/FWaaS/API_1.0"

    @classmethod
    def get_updated(cls):
        return "2013-02-25T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        my_plurals = []
        for plural in RESOURCE_ATTRIBUTE_MAP:
            if plural == 'firewall_policies':
                singular = 'firewall_policy'
            else:
                singular = plural[:-1]
            my_plurals.append((plural, singular))
        attr.PLURALS.update(dict(my_plurals))
        resources = []
        plugin = manager.NeutronManager.get_service_plugins()[
            constants.FIREWALL]
        for collection_name in RESOURCE_ATTRIBUTE_MAP:
            # Special handling needed for resources with 'y' ending
            if collection_name == 'firewall_policies':
                resource_name = 'firewall_policy'
            else:
                resource_name = collection_name[:-1]

            params = RESOURCE_ATTRIBUTE_MAP[collection_name]

            member_actions = {}
            if resource_name == 'firewall_policy':
                member_actions = {'insert_rule': 'PUT',
                                  'remove_rule': 'PUT'}

            controller = base.create_resource(
                collection_name, resource_name, plugin, params,
                member_actions=member_actions,
                allow_pagination=cfg.CONF.allow_pagination,
                allow_sorting=cfg.CONF.allow_sorting)

            resource = extensions.ResourceExtension(
                collection_name,
                controller,
                path_prefix=constants.COMMON_PREFIXES[constants.FIREWALL],
                member_actions=member_actions,
                attr_map=params)
            resources.append(resource)

        return resources

    @classmethod
    def get_plugin_interface(cls):
        return FirewallPluginBase

    def update_attributes_map(self, attributes):
        super(Firewall, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


class FirewallPluginBase(ServicePluginBase):
    __metaclass__ = abc.ABCMeta

    def get_plugin_name(self):
        return constants.FIREWALL

    def get_plugin_type(self):
        return constants.FIREWALL

    def get_plugin_description(self):
        return 'Firewall service plugin'

    @abc.abstractmethod
    def get_firewalls(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_firewall(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_firewall(self, context, firewall):
        pass

    @abc.abstractmethod
    def update_firewall(self, context, id, firewall):
        pass

    @abc.abstractmethod
    def delete_firewall(self, context, id):
        pass

    @abc.abstractmethod
    def get_firewall_rules(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_firewall_rule(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_firewall_rule(self, context, firewall_rule):
        pass

    @abc.abstractmethod
    def update_firewall_rule(self, context, id, firewall_rule):
        pass

    @abc.abstractmethod
    def delete_firewall_rule(self, context, id):
        pass

    @abc.abstractmethod
    def get_firewall_policy(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def get_firewall_policies(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def create_firewall_policy(self, context, firewall_policy):
        pass

    @abc.abstractmethod
    def update_firewall_policy(self, context, id, firewall_policy):
        pass

    @abc.abstractmethod
    def delete_firewall_policy(self, context, id):
        pass

    @abc.abstractmethod
    def insert_rule(self, context, id, rule_info):
        pass

    @abc.abstractmethod
    def remove_rule(self, context, id, rule_info):
        pass
