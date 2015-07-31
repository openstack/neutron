# Copyright (c) 2015 Huawei Technologies Co.,LTD.
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

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import base
from neutron.common import exceptions as nexception
from neutron import manager
import six

ADDRESS_SCOPE = 'address_scope'
ADDRESS_SCOPES = '%ss' % ADDRESS_SCOPE


# Attribute Map
RESOURCE_ATTRIBUTE_MAP = {
    ADDRESS_SCOPES: {
        'id': {'allow_post': False,
               'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True,
                 'allow_put': True,
                 'default': '',
                 'validate': {'type:string': attr.NAME_MAX_LEN},
                 'is_visible': True},
        'tenant_id': {'allow_post': True,
                      'allow_put': False,
                      'validate': {'type:string': attr.TENANT_ID_MAX_LEN},
                      'required_by_policy': True,
                      'is_visible': True},
        attr.SHARED: {'allow_post': True,
                      'allow_put': True,
                      'default': False,
                      'convert_to': attr.convert_to_boolean,
                      'is_visible': True,
                      'required_by_policy': True,
                      'enforce_policy': True},
    }
}


class AddressScopeNotFound(nexception.NotFound):
    message = _("Address scope %(address_scope_id)s could not be found")


class AddressScopeDeleteError(nexception.BadRequest):
    message = _("Unable to delete address scope %(address_scope_id)s : "
                "%(reason)s")


class AddressScopeUpdateError(nexception.BadRequest):
    message = _("Unable to update address scope %(address_scope_id)s : "
                "%(reason)s")


class Address_scope(extensions.ExtensionDescriptor):
    """Extension class supporting Address Scopes."""

    @classmethod
    def get_name(cls):
        return "Address scope"

    @classmethod
    def get_alias(cls):
        return "address-scope"

    @classmethod
    def get_description(cls):
        return "Address scopes extension."

    @classmethod
    def get_updated(cls):
        return "2015-07-26T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        my_plurals = [(key, key[:-1]) for key in RESOURCE_ATTRIBUTE_MAP.keys()]
        attr.PLURALS.update(dict(my_plurals))
        plugin = manager.NeutronManager.get_plugin()
        collection_name = ADDRESS_SCOPES.replace('_', '-')
        params = RESOURCE_ATTRIBUTE_MAP.get(ADDRESS_SCOPES, dict())
        controller = base.create_resource(collection_name,
                                          ADDRESS_SCOPE,
                                          plugin, params, allow_bulk=True,
                                          allow_pagination=True,
                                          allow_sorting=True)

        ex = extensions.ResourceExtension(collection_name, controller,
                                          attr_map=params)
        return [ex]

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class AddressScopePluginBase(object):

    @abc.abstractmethod
    def create_address_scope(self, context, address_scope):
        pass

    @abc.abstractmethod
    def update_address_scope(self, context, id, address_scope):
        pass

    @abc.abstractmethod
    def get_address_scope(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def get_address_scopes(self, context, filters=None, fields=None,
                           sorts=None, limit=None, marker=None,
                           page_reverse=False):
        pass

    @abc.abstractmethod
    def delete_address_scope(self, context, id):
        pass

    def get_address_scopes_count(self, context, filters=None):
        raise NotImplementedError()
