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

import six

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import base
from neutron.api.v2 import resource_helper
from neutron import manager
from neutron.plugins.common import constants
from neutron.services.qos import qos_consts
from neutron.services import service_base

QOS_PREFIX = "/qos"

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

RESOURCE_ATTRIBUTE_MAP = {
    'policies': {
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
                      'is_visible': True},
        'rules': {'allow_post': False, 'allow_put': False, 'is_visible': True},
    },
    'rule_types': {
        'type': {'allow_post': False, 'allow_put': False,
                 'is_visible': True}
    }
}

SUB_RESOURCE_ATTRIBUTE_MAP = {
    'bandwidth_limit_rules': {
        'parent': {'collection_name': 'policies',
                   'member_name': 'policy'},
        'parameters': dict(QOS_RULE_COMMON_FIELDS,
                           **{'max_kbps': {
                                  'allow_post': True, 'allow_put': True,
                                  'is_visible': True, 'default': None,
                                  'validate': {'type:non_negative': None}},
                              'max_burst_kbps': {
                                  'allow_post': True, 'allow_put': True,
                                  'is_visible': True, 'default': 0,
                                  'validate': {'type:non_negative': None}}})
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


class Qos(extensions.ExtensionDescriptor):
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
        attr.PLURALS.update(plural_mappings)

        resources = resource_helper.build_resource_info(
                plural_mappings,
                RESOURCE_ATTRIBUTE_MAP,
                constants.QOS,
                translate_name=True,
                allow_bulk=True)

        plugin = manager.NeutronManager.get_service_plugins()[constants.QOS]
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
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return dict(list(EXTENDED_ATTRIBUTES_2_0.items()) +
                        list(RESOURCE_ATTRIBUTE_MAP.items()))
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class QoSPluginBase(service_base.ServicePluginBase):

    path_prefix = QOS_PREFIX

    def get_plugin_description(self):
        return "QoS Service Plugin for ports and networks"

    def get_plugin_type(self):
        return constants.QOS

    @abc.abstractmethod
    def get_policy(self, context, policy_id, fields=None):
        pass

    @abc.abstractmethod
    def get_policies(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None,
                     page_reverse=False):
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
    def get_policy_bandwidth_limit_rule(self, context, rule_id,
                                        policy_id, fields=None):
        pass

    @abc.abstractmethod
    def get_policy_bandwidth_limit_rules(self, context, policy_id,
                                         filters=None, fields=None,
                                         sorts=None, limit=None,
                                         marker=None, page_reverse=False):
        pass

    @abc.abstractmethod
    def create_policy_bandwidth_limit_rule(self, context, policy_id,
                                           bandwidth_limit_rule):
        pass

    @abc.abstractmethod
    def update_policy_bandwidth_limit_rule(self, context, rule_id, policy_id,
                                           bandwidth_limit_rule):
        pass

    @abc.abstractmethod
    def delete_policy_bandwidth_limit_rule(self, context, rule_id, policy_id):
        pass

    @abc.abstractmethod
    def get_rule_types(self, context, filters=None, fields=None,
                       sorts=None, limit=None,
                       marker=None, page_reverse=False):
        pass
