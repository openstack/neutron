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

import six

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import resource_helper
from neutron.plugins.common import constants
from neutron.services import service_base

VALID_RULE_TYPES = ['bandwidth_limit']

# Attribute Map
QOS_RULE_COMMON_FIELDS = {
    'id': {'allow_post': False, 'allow_put': False,
           'validate': {'type:uuid': None},
           'is_visible': True,
           'primary_key': True},
    'qos_policy_id': {'allow_post': True, 'allow_put': False,
                      'is_visible': True, 'required_by_policy': True},
    'type': {'allow_post': True, 'allow_put': True, 'is_visible': True,
             'default': '',
             'validate': {'type:values': VALID_RULE_TYPES}},
    'tenant_id': {'allow_post': True, 'allow_put': False,
                  'required_by_policy': True,
                  'is_visible': True}}

RESOURCE_ATTRIBUTE_MAP = {
    'qos_policies': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
        'is_visible': True, 'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'is_visible': True, 'default': '',
                 'validate': {'type:string': None}},
        'description': {'allow_post': True, 'allow_put': True,
                        'is_visible': True, 'default': '',
                        'validate': {'type:string': None}},
        'shared': {'allow_post': True, 'allow_put': True,
                   'is_visible': True, 'default': False,
                   'convert_to': attr.convert_to_boolean},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True}},
    #TODO(QoS): Here instead of using the resource helper we may
    #           need to set a subcontroller for qos-rules, so we
    #           can meet the spec definition.
    'qos_bandwidthlimit_rules':
        dict(QOS_RULE_COMMON_FIELDS,
            **{'max_kbps': {'allow_post': True, 'allow_put': True,
                            'is_visible': True, 'default': None,
                            'validate': {'type:non_negative', None}},
               'max_burst_kbps': {'allow_post': True, 'allow_put': True,
                                  'is_visible': True, 'default': 0,
                                  'validate': {'type:non_negative', None}}})}

QOS_POLICY_ID = "qos_policy_id"

EXTENDED_ATTRIBUTES_2_0 = {
    'ports': {QOS_POLICY_ID: {'allow_post': True,
                              'allow_put': True,
                              'is_visible': True,
                              'default': None,
                              'validate': {'type:uuid_or_none': None}}},
    'networks': {QOS_POLICY_ID: {'allow_post': True,
                                 'allow_put': True,
                                 'is_visible': True,
                                 'default': None,
                                 'validate': {'type:uuid_or_none': None}}}}


class Qos(extensions.ExtensionDescriptor):
    """Quality of service API extension."""

    @classmethod
    def get_name(cls):
        return "qos"

    @classmethod
    def get_alias(cls):
        return "qos"

    @classmethod
    def get_namespace(cls):
        #TODO(QoS): Remove, there's still a caller using it for log/debug
        #           which will crash otherwise
        return None

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
        plural_mappings = resource_helper.build_plural_mappings(
            {'policies': 'policy'}, RESOURCE_ATTRIBUTE_MAP)
        attr.PLURALS.update(plural_mappings)
        #TODO(QoS): manually register some resources to make sure
        #           we match what's defined in the spec.
        return resource_helper.build_resource_info(plural_mappings,
                                                   RESOURCE_ATTRIBUTE_MAP,
                                                   constants.QOS,
                                                   translate_name=True,
                                                   allow_bulk=True)

    def get_extended_resources(self, version):
        if version == "2.0":
            return dict(EXTENDED_ATTRIBUTES_2_0.items() +
                        RESOURCE_ATTRIBUTE_MAP.items())
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class QoSPluginBase(service_base.ServicePluginBase):

    def get_plugin_description(self):
        """returns string description of the plugin."""
        return "QoS Service Plugin for ports and networks"

    def get_plugin_type(self):
        return constants.QOS

    @abc.abstractmethod
    def get_qos_policy(self, context, qos_policy_id, fields=None):
        pass

    @abc.abstractmethod
    def get_qos_policies(self, context, filters=None, fields=None,
                         sorts=None, limit=None, marker=None,
                         page_reverse=False):
        pass

    @abc.abstractmethod
    def create_qos_policy(self, context, qos_policy):
        pass

    @abc.abstractmethod
    def update_qos_policy(self, context, qos_policy_id, qos_policy):
        pass

    @abc.abstractmethod
    def delete_qos_policy(self, context, qos_policy_id):
        pass

    @abc.abstractmethod
    def get_qos_bandwidth_limit_rule(self, context, rule_id, fields=None):
        pass

    @abc.abstractmethod
    def get_qos_bandwith_limit_rules(self, context, filters=None, fields=None,
                                     sorts=None, limit=None, marker=None,
                                     page_reverse=False):
        pass

    @abc.abstractmethod
    def create_qos_bandwidth_limit_rule(self, context, rule):
        pass

    @abc.abstractmethod
    def update_qos_bandwidth_limit_rule(self, context, rule_id, rule):
        pass

    @abc.abstractmethod
    def delete_qos_bandwith_limit_rule(self, context, rule_id):
        pass
