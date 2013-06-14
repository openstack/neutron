# Copyright (C) 2013 eNovance SAS <licensing@enovance.com>
#
# Author: Sylvain Afchain <sylvain.afchain@enovance.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import abc

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import base
from neutron.common import exceptions as qexception
from neutron import manager
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants
from neutron.services import service_base

LOG = logging.getLogger(__name__)


class MeteringLabelNotFound(qexception.NotFound):
    message = _("Metering label %(label_id)s does not exist")


class DuplicateMeteringRuleInPost(qexception.InUse):
    message = _("Duplicate Metering Rule in POST.")


class MeteringLabelRuleNotFound(qexception.NotFound):
    message = _("Metering label rule %(rule_id)s does not exist")


class MeteringLabelRuleOverlaps(qexception.NotFound):
    message = _("Metering label rule with remote_ip_prefix "
                "%(remote_ip_prefix)s overlaps another")


RESOURCE_ATTRIBUTE_MAP = {
    'metering_labels': {
        'id': {'allow_post': False, 'allow_put': False,
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'is_visible': True, 'default': ''},
        'description': {'allow_post': True, 'allow_put': True,
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True}
    },
    'metering_label_rules': {
        'id': {'allow_post': False, 'allow_put': False,
               'is_visible': True,
               'primary_key': True},
        'metering_label_id': {'allow_post': True, 'allow_put': False,
                              'validate': {'type:uuid': None},
                              'is_visible': True, 'required_by_policy': True},
        'direction': {'allow_post': True, 'allow_put': True,
                      'is_visible': True,
                      'validate': {'type:values': ['ingress', 'egress']}},
        'excluded': {'allow_post': True, 'allow_put': True,
                     'is_visible': True, 'default': False,
                     'convert_to': attr.convert_to_boolean},
        'remote_ip_prefix': {'allow_post': True, 'allow_put': False,
                             'is_visible': True, 'required_by_policy': True,
                             'validate': {'type:subnet': None}},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True}
    }
}


class Metering(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Neutron Metering"

    @classmethod
    def get_alias(cls):
        return "metering"

    @classmethod
    def get_description(cls):
        return "Neutron Metering extension."

    @classmethod
    def get_namespace(cls):
        return "http://wiki.openstack.org/wiki/Neutron/Metering/Bandwidth#API"

    @classmethod
    def get_updated(cls):
        return "2013-06-12T10:00:00-00:00"

    @classmethod
    def get_plugin_interface(cls):
        return MeteringPluginBase

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        my_plurals = [(key, key[:-1]) for key in RESOURCE_ATTRIBUTE_MAP.keys()]
        attr.PLURALS.update(dict(my_plurals))
        exts = []
        plugin = manager.NeutronManager.get_service_plugins()[
            constants.METERING]
        for resource_name in ['metering_label', 'metering_label_rule']:
            collection_name = resource_name + "s"

            collection_name = collection_name.replace('_', '-')
            params = RESOURCE_ATTRIBUTE_MAP.get(resource_name + "s", dict())

            controller = base.create_resource(collection_name,
                                              resource_name,
                                              plugin, params, allow_bulk=True,
                                              allow_pagination=True,
                                              allow_sorting=True)

            ex = extensions.ResourceExtension(
                collection_name,
                controller,
                path_prefix=constants.COMMON_PREFIXES[constants.METERING],
                attr_map=params)
            exts.append(ex)

        return exts

    def update_attributes_map(self, attributes):
        super(Metering, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


class MeteringPluginBase(service_base.ServicePluginBase):
    __metaclass__ = abc.ABCMeta

    def get_plugin_name(self):
        return constants.METERING

    def get_plugin_description(self):
        return constants.METERING

    def get_plugin_type(self):
        return constants.METERING

    @abc.abstractmethod
    def create_metering_label(self, context, metering_label):
        """Create a metering label."""
        pass

    @abc.abstractmethod
    def delete_metering_label(self, context, label_id):
        """Delete a metering label."""
        pass

    @abc.abstractmethod
    def get_metering_label(self, context, label_id, fields=None):
        """Get a metering label."""
        pass

    @abc.abstractmethod
    def get_metering_labels(self, context, filters=None, fields=None,
                            sorts=None, limit=None, marker=None,
                            page_reverse=False):
        """List all metering labels."""
        pass

    @abc.abstractmethod
    def create_metering_label_rule(self, context, metering_label_rule):
        """Create a metering label rule."""
        pass

    @abc.abstractmethod
    def get_metering_label_rule(self, context, rule_id, fields=None):
        """Get a metering label rule."""
        pass

    @abc.abstractmethod
    def delete_metering_label_rule(self, context, rule_id):
        """Delete a metering label rule."""
        pass

    @abc.abstractmethod
    def get_metering_label_rules(self, context, filters=None, fields=None,
                                 sorts=None, limit=None, marker=None,
                                 page_reverse=False):
        """List all metering label rules."""
        pass
