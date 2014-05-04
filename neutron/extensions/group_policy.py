# Copyright 2014 OpenStack Foundation.
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

import abc

import six

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import resource_helper
from neutron.common import exceptions as nexc
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants
from neutron.services.service_base import ServicePluginBase


LOG = logging.getLogger(__name__)


# Group Policy Exceptions
class EndpointNotFound(nexc.NotFound):
    message = _("Endpoint %(endpoint_id)s could not be found")


class EndpointGroupNotFound(nexc.NotFound):
    message = _("EndpointGroup %(endpoint_group_id)s could not be found")


class ContractNotFound(nexc.NotFound):
    message = _("Contract %(contract_id)s could not be found")


class ContractScopeNotFound(nexc.NotFound):
    message = _("ContractScope %(contract_scope_id)s could not be found")


class PolicyRuleNotFound(nexc.NotFound):
    message = _("PolicyRule %(policy_rule_id)s could not be found")


class BridgeDomainNotFound(nexc.NotFound):
    message = _("BridgeDomain %(bridge_domain_id)s could not be found")


class RoutingDomainNotFound(nexc.NotFound):
    message = _("RoutingDomain %(routing_domain_id)s could not be found")


class GroupPolicyInvalidPortValue(nexc.InvalidInput):
    message = _("Invalid value for port %(port)s")


class GroupPolicyInvalidProtocol(nexc.InvalidInput):
    message = _("Protocol %(protocol)s is not supported. "
                "Only protocol values %(values)s and their integer "
                "representation (0 to 255) are supported.")


# Group Policy Values
gp_supported_actions = [None, constants.GP_ALLOW, constants.GP_REDIRECT]
gp_supported_directions = [None, constants.GP_DIRECTION_IN,
                           constants.GP_DIRECTION_OUT,
                           constants.GP_DIRECTION_BI]
gp_supported_protocols = [None, constants.TCP, constants.UDP, constants.ICMP]
gp_supported_scopes = [None, constants.GP_GLOBAL, constants.GP_TENANT,
                       constants.GP_EPG]


# Group Policy input value conversion and validation functions
def convert_protocol(value):
    if value is None:
        return
    if value.isdigit():
        val = int(value)
        if 0 <= val <= 255:
            return val
        else:
            raise GroupPolicyInvalidProtocol(protocol=value,
                                             values=gp_supported_protocols)
    elif value.lower() in gp_supported_protocols:
        return value.lower()
    else:
        raise GroupPolicyInvalidProtocol(protocol=value,
                                         values=
                                         gp_supported_protocols)


def convert_action_to_case_insensitive(value):
    if value is None:
        return
    else:
        return value.lower()


def convert_scope_to_case_insensitive(value):
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


def convert_validate_port_value(port):
    if port is None:
        return port
    try:
        val = int(port)
    except (ValueError, TypeError):
        raise GroupPolicyInvalidPortValue(port=port)

    if val >= 0 and val <= 65535:
        return val
    else:
        raise GroupPolicyInvalidPortValue(port=port)


ENDPOINTS = 'endpoints'
ENDPOINT_GROUPS = 'endpoint_groups'
CONTRACTS = 'contracts'
CONTRACT_PROVIDING_SCOPES = 'contract_providing_scopes'
CONTRACT_CONSUMING_SCOPES = 'contract_consuming_scopes'
POLICY_RULES = 'policy_rules'
FILTERS = 'filters'
CLASSIFIERS = 'classifiers'
ACTIONS = 'actions'
SELECTORS = 'selectors'
POLICY_LABELS = 'policy_labels'
BRIDGE_DOMAINS = 'bridge_domains'
ROUTING_DOMAINS = 'routing_domains'

RESOURCE_ATTRIBUTE_MAP = {
    ENDPOINTS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None}, 'default': '',
                 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True, 'is_visible': True},
        'endpoint_group_id': {'allow_post': True, 'allow_put': True,
                              'validate': {'type:uuid_or_none': None},
                              'required': True, 'is_visible': True},
    },
    ENDPOINT_GROUPS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True, 'is_visible': True},
        'endpoints': {'allow_post': False, 'allow_put': False,
                      'validate': {'type:uuid_list': None},
                      'convert_to': attr.convert_none_to_empty_list,
                      'default': None, 'is_visible': True},
        'bridge_domain_id': {'allow_post': True, 'allow_put': True,
                             'validate': {'type:uuid_or_none': None},
                             'default': None, 'is_visible': True},
        'provided_contract_scopes': {'allow_post': True, 'allow_put': True,
                                     'validate': {'type:uuid_list': None},
                                     'convert_to':
                                     attr.convert_none_to_empty_list,
                                     'default': None, 'is_visible': True},
        'consumed_contract_scopes': {'allow_post': True, 'allow_put': True,
                                     'validate': {'type:uuid_list': None},
                                     'convert_to':
                                     attr.convert_none_to_empty_list,
                                     'default': None, 'is_visible': True},
    },
    CONTRACTS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'default': '',
                 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'child_contracts': {'allow_post': True, 'allow_put': True,
                            'default': None,
                            'validate': {'type:uuid_list': None},
                            'convert_to': attr.convert_none_to_empty_list,
                            'required': True, 'is_visible': True},
        'policy_rules': {'allow_post': True, 'allow_put': True,
                         'default': None,
                         'validate': {'type:uuid_list': None},
                         'convert_to': attr.convert_none_to_empty_list,
                         'required': True, 'is_visible': True},
    },
    CONTRACT_PROVIDING_SCOPES: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'default': '',
                 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'endpointgroup_id': {'allow_post': True, 'allow_put': True,
                             'validate': {'type:uuid': None},
                             'required': True, 'is_visible': True},
        'contract_id': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:uuid': None},
                        'required': True, 'is_visible': True},
        'selector_id': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:uuid_or_none': None},
                        'required': True, 'is_visible': True},
        'capabilities': {'allow_post': True, 'allow_put': True,
                         'default': None,
                         'validate': {'type:uuid_list': None},
                         'convert_to': attr.convert_none_to_empty_list,
                         'required': True, 'is_visible': True},
    },
    CONTRACT_CONSUMING_SCOPES: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True, 'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'default': '',
                 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'endpointgroup_id': {'allow_post': True, 'allow_put': True,
                             'validate': {'type:uuid': None},
                             'required': True, 'is_visible': True},
        'contract_id': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:uuid': None},
                        'required': True, 'is_visible': True},
        'selector_id': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:uuid_or_none': None},
                        'required': True, 'is_visible': True},
        'roles': {'allow_post': True, 'allow_put': True,
                  'default': None,
                  'validate': {'type:uuid_list': None},
                  'convert_to': attr.convert_none_to_empty_list,
                  'required': True, 'is_visible': True},
    },
    POLICY_RULES: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True, 'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'enabled': {'allow_post': True, 'allow_put': True,
                    'default': True, 'convert_to': attr.convert_to_boolean,
                    'is_visible': True},
        'filter_id': {'allow_post': True, 'allow_put': True,
                      'validate': {'type:uuid_or_none': None},
                      'required': True, 'is_visible': True},
        'classifier_id': {'allow_post': True, 'allow_put': True,
                          'validate': {'type:uuid': None},
                          'required': True, 'is_visible': True},
        'actions': {'allow_post': True, 'allow_put': True,
                    'default': None,
                    'validate': {'type:uuid_list': None},
                    'convert_to': attr.convert_none_to_empty_list,
                    'required': True, 'is_visible': True},
    },
    FILTERS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True, 'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'provider_capabilities': {'allow_post': True, 'allow_put': True,
                                  'validate': {'type:uuid_list': None},
                                  'convert_to':
                                  attr.convert_none_to_empty_list,
                                  'required': True, 'is_visible': True},
        'consumer_roles': {'allow_post': True, 'allow_put': True,
                           'validate': {'type:uuid_list': None},
                           'convert_to': attr.convert_none_to_empty_list,
                           'required': True, 'is_visible': True},
    },
    CLASSIFIERS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True, 'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'protocol': {'allow_post': True, 'allow_put': True,
                     'is_visible': True, 'default': None,
                     'convert_to': convert_protocol,
                     'validate': {'type:values': gp_supported_protocols}},
        'port_range': {'allow_post': True, 'allow_put': True,
                       'validate': {'type:port_range': None},
                       'convert_to': convert_port_to_string,
                       'default': None, 'is_visible': True},
        'direction': {'allow_post': True, 'allow_put': True,
                      'validate': {'type:string': gp_supported_directions},
                      'default': None, 'is_visible': True},
    },
    ACTIONS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'action_type': {'allow_post': True, 'allow_put': True,
                        'convert_to': convert_action_to_case_insensitive,
                        'validate': {'type:values': gp_supported_actions},
                        'is_visible': True, 'default': 'allow'},
        'action_value': {'allow_post': True, 'allow_put': True,
                         'validate': {'type:uuid_or_none': None},
                         'is_visible': True},
    },
    SELECTORS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'scope': {'allow_post': True, 'allow_put': True,
                  'convert_to': convert_scope_to_case_insensitive,
                  'validate': {'type:values': gp_supported_scopes},
                  'is_visible': True, 'default': 'tenant'},
        'value': {'allow_post': True, 'allow_put': True,
                  'validate': {'type:uuid_or_none': None},
                  'is_visible': True},
    },
    POLICY_LABELS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'namespace': {'allow_post': True, 'allow_put': True,
                      'validate': {'type:string': None},
                      'is_visible': True, 'default': ''},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': True, 'required': True},
    },
    BRIDGE_DOMAINS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True, 'is_visible': True},
        'endpoint_groups': {'allow_post': False, 'allow_put': False,
                            'validate': {'type:uuid_list': None},
                            'convert_to': attr.convert_none_to_empty_list,
                            'default': None, 'is_visible': True},
        'routing_domain_id': {'allow_post': True, 'allow_put': True,
                              'validate': {'type:uuid_or_none': None},
                              'default': None, 'is_visible': True,
                              'required': True},
    },
    ROUTING_DOMAINS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True, 'is_visible': True},
        'ip_version': {'allow_post': True, 'allow_put': False,
                       'convert_to': attr.convert_to_int,
                       'validate': {'type:values': [4, 6]},
                       'default': 4, 'is_visible': True},
        'ip_supernet': {'allow_post': True, 'allow_put': False,
                        'validate': {'type:subnet': None},
                        'is_visible': True},
        'subnet_prefix_length': {'allow_post': True, 'allow_put': True,
                                 'convert_to': attr.convert_to_int,
                                 'validate': {'type:values': range(30)},
                                 'default': 24, 'is_visible': True},
        'bridge_domains': {'allow_post': False, 'allow_put': False,
                           'validate': {'type:uuid_list': None},
                           'convert_to': attr.convert_none_to_empty_list,
                           'default': None, 'is_visible': True},
    },
}

# TODO(sumit): Add quota opts


class Group_policy(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Group Policy Abstraction"

    @classmethod
    def get_alias(cls):
        return "group-policy"

    @classmethod
    def get_description(cls):
        return "Extension for Group Policy Abstraction"

    @classmethod
    def get_namespace(cls):
        return "http://wiki.openstack.org/neutron/gp/v1.0/"

    @classmethod
    def get_updated(cls):
        return "2014-03-03T122:00:00-00:00"

    @classmethod
    def get_resources(cls):
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        attr.PLURALS.update(plural_mappings)
        return resource_helper.build_resource_info(plural_mappings,
                                                   RESOURCE_ATTRIBUTE_MAP,
                                                   constants.GROUP_POLICY)

    @classmethod
    def get_plugin_interface(cls):
        return GroupPolicyPluginBase

    def update_attributes_map(self, attributes):
        super(Group_policy, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class GroupPolicyPluginBase(ServicePluginBase):

    def get_plugin_name(self):
        return constants.GROUP_POLICY

    def get_plugin_type(self):
        return constants.GROUP_POLICY

    def get_plugin_description(self):
        return 'Group Policy plugin'

    @abc.abstractmethod
    def get_endpoints(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_endpoint(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_endpoint(self, context, endpoint):
        pass

    @abc.abstractmethod
    def update_endpoint(self, context, id, endpoint):
        pass

    @abc.abstractmethod
    def delete_endpoint(self, context, id):
        pass

    @abc.abstractmethod
    def get_endpoint_groups(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_endpoint_group(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_endpoint_group(self, context, endpoint_group):
        pass

    @abc.abstractmethod
    def update_endpoint_group(self, context, id, endpoint_group):
        pass

    @abc.abstractmethod
    def delete_endpoint_group(self, context, id):
        pass

    @abc.abstractmethod
    def create_contract(self, context, contract):
        pass

    @abc.abstractmethod
    def update_contract(self, context, id, contract):
        pass

    @abc.abstractmethod
    def get_contracts(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_contract(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def delete_contract(self, context, id):
        pass

    @abc.abstractmethod
    def create_contract_scope(self, context, contract_scope):
        pass

    @abc.abstractmethod
    def update_contract_scope(self, context, id, contract_scope):
        pass

    @abc.abstractmethod
    def get_contract_scopes(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_contract_scope(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def delete_contract_scope(self, context, id):
        pass

    @abc.abstractmethod
    def get_policy_rules(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_policy_rule(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_policy_rule(self, context, policy_rule):
        pass

    @abc.abstractmethod
    def update_policy_rule(self, context, id, policy_rule):
        pass

    @abc.abstractmethod
    def delete_policy_rule(self, context, id):
        pass

    @abc.abstractmethod
    def get_bridge_domains(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_bridge_domain(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_bridge_domain(self, context, bridge_domain):
        pass

    @abc.abstractmethod
    def update_bridge_domain(self, context, id, bridge_domain):
        pass

    @abc.abstractmethod
    def delete_bridge_domain(self, context, id):
        pass

    @abc.abstractmethod
    def get_routing_domains(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_routing_domain(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_routing_domain(self, context, routing_domain):
        pass

    @abc.abstractmethod
    def update_routing_domain(self, context, id, routing_domain):
        pass

    @abc.abstractmethod
    def delete_routing_domain(self, context, id):
        pass
