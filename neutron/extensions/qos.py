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

from neutron_lib.api.definitions import qos as apidef
from neutron_lib.api import extensions as api_extensions
from neutron_lib.plugins import constants
from neutron_lib.plugins import directory
from neutron_lib.services import base as service_base
import six

from neutron.api import extensions
from neutron.api.v2 import base
from neutron.api.v2 import resource_helper
from neutron.objects.qos import rule as rule_object


class Qos(api_extensions.APIExtensionDescriptor):
    """Quality of Service API extension."""

    api_definition = apidef

    @classmethod
    def get_plugin_interface(cls):
        return QoSPluginBase

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        special_mappings = {'policies': 'policy'}
        plural_mappings = resource_helper.build_plural_mappings(
            special_mappings, itertools.chain(
                apidef.RESOURCE_ATTRIBUTE_MAP,
                apidef.SUB_RESOURCE_ATTRIBUTE_MAP))

        resources = resource_helper.build_resource_info(
                plural_mappings,
                apidef.RESOURCE_ATTRIBUTE_MAP,
                constants.QOS,
                translate_name=True,
                allow_bulk=True)

        plugin = directory.get_plugin(constants.QOS)
        for collection_name in apidef.SUB_RESOURCE_ATTRIBUTE_MAP:
            resource_name = collection_name[:-1]
            parent = apidef.SUB_RESOURCE_ATTRIBUTE_MAP[
                collection_name].get('parent')
            params = apidef.SUB_RESOURCE_ATTRIBUTE_MAP[collection_name].get(
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
                path_prefix=apidef.API_PREFIX,
                attr_map=params)
            resources.append(resource)

        return resources

    def update_attributes_map(self, attributes, extension_attrs_map=None):
        # TODO(boden): remove with I8ae11633962a48de6e8559b85447b8c8c753d705
        super(Qos, self).update_attributes_map(
            attributes,
            extension_attrs_map=dict(
                list(apidef.RESOURCE_ATTRIBUTE_MAP.items()) +
                list(apidef.SUB_RESOURCE_ATTRIBUTE_MAP.items())))

    def get_extended_resources(self, version):
        # TODO(boden): remove with I8ae11633962a48de6e8559b85447b8c8c753d705
        if version == "2.0":
            return dict(list(apidef.RESOURCE_ATTRIBUTE_MAP.items()) +
                        list(apidef.SUB_RESOURCE_ATTRIBUTE_MAP.items()))
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class QoSPluginBase(service_base.ServicePluginBase):

    path_prefix = apidef.API_PREFIX

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
