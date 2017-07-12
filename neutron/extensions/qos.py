# Copyright (c) 2015 Red Hat Inc.
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
import itertools
import re

from neutron_lib.api import converters
from neutron_lib.api import extensions as api_extensions
from neutron_lib.db import constants as db_const
from neutron_lib.plugins import directory
from neutron_lib.services import base as service_base
import six

from neutron.api import extensions
from neutron.api.v2 import base
from neutron.api.v2 import resource_helper
from neutron.common import constants as common_constants
from neutron.objects.qos import rule as rule_object
from neutron.plugins.common import constants
from neutron.services.qos import qos_consts


ALIAS = "qos"
QOS_PREFIX = "/qos"
COLLECTION_NAME = 'policies'

# Attribute Map
QOS_RULE_COMMON_FIELDS = {
    'id': {'allow_post': False, 'allow_put': False,
           'validate': {'type:uuid': None},
           'is_visible': True,
           'primary_key': True},
    'tenant_id': {'allow_post': True, 'allow_put': False,
                  'required_by_policy': True,
                  'is_visible': True},
}

RULE_TYPES = "rule_types"

RESOURCE_ATTRIBUTE_MAP = {
    COLLECTION_NAME: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True, 'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'is_visible': True, 'default': '',
                 'validate': {'type:string': db_const.NAME_FIELD_SIZE}},
        'shared': {'allow_post': True, 'allow_put': True,
                   'is_visible': True, 'default': False,
                   'convert_to': converters.convert_to_boolean},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'validate': {
                          'type:string': db_const.PROJECT_ID_FIELD_SIZE},
                      'is_visible': True},
        'rules': {'allow_post': False, 'allow_put': False, 'is_visible': True},
    },
    RULE_TYPES: {
        'type': {'allow_post': False, 'allow_put': False,
                 'is_visible': True}
    }
}

BANDWIDTH_LIMIT_RULES = "bandwidth_limit_rules"

SUB_RESOURCE_ATTRIBUTE_MAP = {
    BANDWIDTH_LIMIT_RULES: {
        'parent': {'collection_name': 'policies',
                   'member_name': 'policy'},
        'parameters': dict(QOS_RULE_COMMON_FIELDS,
                           **{'max_kbps': {
                                  'allow_post': True, 'allow_put': True,
                                  'is_visible': True, 'default': None,
                                  'validate': {'type:range': [0,
                                      common_constants.DB_INTEGER_MAX_VALUE]}},
                              'max_burst_kbps': {
                                  'allow_post': True, 'allow_put': True,
                                  'is_visible': True, 'default': 0,
                                  'validate': {'type:range': [0,
                                  common_constants.DB_INTEGER_MAX_VALUE]}}}),
    },
    'dscp_marking_rules': {
        'parent': {'collection_name': 'policies',
                   'member_name': 'policy'},
        'parameters': dict(QOS_RULE_COMMON_FIELDS,
                           **{'dscp_mark': {
                                  'allow_post': True, 'allow_put': True,
                                  'convert_to': converters.convert_to_int,
                                  'is_visible': True, 'default': None,
                                  'validate': {'type:values': common_constants.
                                              VALID_DSCP_MARKS}}})
    },
    'minimum_bandwidth_rules': {
        'parent': {'collection_name': 'policies',
                   'member_name': 'policy'},
        'parameters': dict(QOS_RULE_COMMON_FIELDS,
                           **{'min_kbps': {
                                  'allow_post': True, 'allow_put': True,
                                  'is_visible': True,
                                  'validate': {'type:range': [0,
                                  common_constants.DB_INTEGER_MAX_VALUE]}},
                              'direction': {
                                  'allow_post': True, 'allow_put': True,
                                  'is_visible': True, 'default': 'egress',
                                  'validate': {'type:values':
                                        [common_constants.EGRESS_DIRECTION]}}})
    }
}

EXTENDED_ATTRIBUTES_2_0 = {
    'ports': {qos_consts.QOS_POLICY_ID: {
                                    'allow_post': True,
                                    'allow_put': True,
                                    'is_visible': True,
                                    'default': None,
                                    'validate': {'type:uuid_or_none': None}}},
    'networks': {qos_consts.QOS_POLICY_ID: {
                                    'allow_post': True,
                                    'allow_put': True,
                                    'is_visible': True,
                                    'default': None,
                                    'validate': {'type:uuid_or_none': None}}}}


class Qos(api_extensions.ExtensionDescriptor):
    """Quality of Service API extension."""

    @classmethod
    def get_name(cls):
        return "Quality of Service"

    @classmethod
    def get_alias(cls):
        return "qos"

    @classmethod
    def get_description(cls):
        return "The Quality of Service extension."

    @classmethod
    def get_updated(cls):
        return "2015-06-08T10:00:00-00:00"

    @classmethod
    def get_plugin_interface(cls):
        return QoSPluginBase

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        special_mappings = {'policies': 'policy'}
        plural_mappings = resource_helper.build_plural_mappings(
            special_mappings, itertools.chain(RESOURCE_ATTRIBUTE_MAP,
                                           SUB_RESOURCE_ATTRIBUTE_MAP))

        resources = resource_helper.build_resource_info(
                plural_mappings,
                RESOURCE_ATTRIBUTE_MAP,
                constants.QOS,
                translate_name=True,
                allow_bulk=True)

        plugin = directory.get_plugin(constants.QOS)
        for collection_name in SUB_RESOURCE_ATTRIBUTE_MAP:
            resource_name = collection_name[:-1]
            parent = SUB_RESOURCE_ATTRIBUTE_MAP[collection_name].get('parent')
            params = SUB_RESOURCE_ATTRIBUTE_MAP[collection_name].get(
                'parameters')

            controller = base.create_resource(collection_name, resource_name,
                                              plugin, params,
                                              allow_bulk=True,
                                              parent=parent,
                                              allow_pagination=True,
                                              allow_sorting=True)

            resource = extensions.ResourceExtension(
                collection_name,
                controller, parent,
                path_prefix=QOS_PREFIX,
                attr_map=params)
            resources.append(resource)

        return resources

    def update_attributes_map(self, attributes, extension_attrs_map=None):
        super(Qos, self).update_attributes_map(
            attributes,
            extension_attrs_map=dict(list(RESOURCE_ATTRIBUTE_MAP.items()) +
                                     list(SUB_RESOURCE_ATTRIBUTE_MAP.items())))

    def get_extended_resources(self, version):
        if version == "2.0":
            return dict(list(EXTENDED_ATTRIBUTES_2_0.items()) +
                        list(RESOURCE_ATTRIBUTE_MAP.items()) +
                        list(SUB_RESOURCE_ATTRIBUTE_MAP.items()))
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class QoSPluginBase(service_base.ServicePluginBase):

    path_prefix = QOS_PREFIX

    # The rule object type to use for each incoming rule-related request.
    rule_objects = {'bandwidth_limit': rule_object.QosBandwidthLimitRule,
                    'dscp_marking': rule_object.QosDscpMarkingRule,
                    'minimum_bandwidth': rule_object.QosMinimumBandwidthRule}

    # Patterns used to call method proxies for all policy-rule-specific
    # method calls (see __getattr__ docstring, below).
    qos_rule_method_patterns = [
            re.compile(
                r"^((create|update|delete)_policy_(?P<rule_type>.*)_rule)$"),
            re.compile(
                r"^(get_policy_(?P<rule_type>.*)_(rules|rule))$"),
                               ]

    def __getattr__(self, attrib):
        """Implement method proxies for all policy-rule-specific requests. For
        a given request type (such as to update a rule), a single method will
        handle requests for all rule types.  For example, the
        update_policy_rule method will handle requests for both
        update_policy_dscp_marking_rule and update_policy_bandwidth_limit_rule.

        :param attrib: the requested method; in the normal case, this will be,
                       for example, "update_policy_dscp_marking_rule"
        :type attrib: str
        """
        # Find and call the proxy method that implements the requested one.
        for pattern in self.qos_rule_method_patterns:
            res = re.match(pattern, attrib)
            if res:
                rule_type = res.group('rule_type')
                if rule_type in self.rule_objects:
                    # Remove the rule_type value (plus underscore) from attrib
                    # in order to get the proxy method name. So, for instance,
                    # from "delete_policy_dscp_marking_rule" we'll get
                    # "delete_policy_rule".
                    proxy_method = attrib.replace(rule_type + '_', '')

                    rule_cls = self.rule_objects[rule_type]
                    return self._call_proxy_method(proxy_method, rule_cls)

        # If we got here, then either attrib matched no pattern or the
        # rule_type embedded in attrib wasn't in self.rule_objects.
        raise AttributeError(attrib)

    def _call_proxy_method(self, method_name, rule_cls):
        """Call proxy method. We need to add the rule_cls, obtained from the
        self.rule_objects dictionary, to the incoming args.  The context is
        passed to proxy method as first argument; the remaining args will
        follow rule_cls.

        Some of the incoming method calls have the policy rule name as one of
        the keys in the kwargs.  For instance, the incoming kwargs for the
        create_policy_bandwidth_limit_rule take this form:

            { 'bandwidth_limit_rule': {
                  u'bandwidth_limit_rule':
                  { 'max_burst_kbps': 0,
                    u'max_kbps': u'100',
                    'tenant_id': u'a8a31c9434ff431cb789c809777505ec'}
                  },
              'policy_id': u'46985da5-9684-402e-b0d7-b7adac909c3a'
            }

        We need to generalize this structure for all rule types so will
        (effectively) rename the rule-specific keyword (e.g., in the above, the
        first occurrence of 'bandwidth_limit_rule') to be 'rule_data'.

        :param method_name: the name of the method to call
        :type method_name: str
        :param rule_cls: the rule class, which is sent as an argument to the
                         proxy method
        :type rule_cls: a class from the rule_object (qos.objects.rule) module
        """
        def _make_call(method_name, rule_cls, *args, **kwargs):
            context = args[0]
            args_list = list(args[1:])
            params = kwargs
            rule_data_name = rule_cls.rule_type + "_rule"
            if rule_data_name in params:
                params['rule_data'] = params.pop(rule_data_name)

            return getattr(self, method_name)(
                context, rule_cls, *args_list, **params
            )

        return lambda *args, **kwargs: _make_call(
            method_name, rule_cls, *args, **kwargs)

    def get_plugin_description(self):
        return "QoS Service Plugin for ports and networks"

    @classmethod
    def get_plugin_type(cls):
        return constants.QOS

    @abc.abstractmethod
    def get_rule_type(self, context, rule_type_name, fields=None):
        pass

    @abc.abstractmethod
    def get_rule_types(self, context, filters=None, fields=None, sorts=None,
                       limit=None, marker=None, page_reverse=False):
        pass

    @abc.abstractmethod
    def create_policy(self, context, policy):
        pass

    @abc.abstractmethod
    def update_policy(self, context, policy_id, policy):
        pass

    @abc.abstractmethod
    def delete_policy(self, context, policy_id):
        pass

    @abc.abstractmethod
    def get_policy(self, context, policy_id, fields=None):
        pass

    @abc.abstractmethod
    def get_policies(self, context, filters=None, fields=None, sorts=None,
                     limit=None, marker=None, page_reverse=False):
        pass

    @abc.abstractmethod
    def create_policy_rule(self, context, rule_cls, policy_id, rule_data):
        pass

    @abc.abstractmethod
    def update_policy_rule(self, context, rule_cls, rule_id, policy_id,
                           rule_data):
        pass

    @abc.abstractmethod
    def delete_policy_rule(self, context, rule_cls, rule_id, policy_id):
        pass

    @abc.abstractmethod
    def get_policy_rule(self, context, rule_cls, rule_id, policy_id,
                        fields=None):
        pass

    @abc.abstractmethod
    def get_policy_rules(self, context, rule_cls, policy_id,
                         filters=None, fields=None, sorts=None, limit=None,
                         marker=None, page_reverse=False):
        pass
