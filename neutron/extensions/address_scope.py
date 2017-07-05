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

from neutron_lib.api import converters
from neutron_lib.api.definitions import network as net_def
from neutron_lib.api.definitions import subnetpool as subnetpool_def
from neutron_lib.api import extensions as api_extensions
from neutron_lib import constants
from neutron_lib.db import constants as db_const
from neutron_lib import exceptions as nexception
from neutron_lib.plugins import directory
import six

from neutron._i18n import _
from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import base

ADDRESS_SCOPE = 'address_scope'
ADDRESS_SCOPES = '%ss' % ADDRESS_SCOPE
ADDRESS_SCOPE_ID = 'address_scope_id'
IPV4_ADDRESS_SCOPE = 'ipv4_%s' % ADDRESS_SCOPE
IPV6_ADDRESS_SCOPE = 'ipv6_%s' % ADDRESS_SCOPE

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
                 'validate': {'type:string': db_const.NAME_FIELD_SIZE},
                 'is_visible': True},
        'tenant_id': {'allow_post': True,
                      'allow_put': False,
                      'validate': {
                          'type:string': db_const.PROJECT_ID_FIELD_SIZE},
                      'required_by_policy': True,
                      'is_visible': True},
        attr.SHARED: {'allow_post': True,
                      'allow_put': True,
                      'default': False,
                      'convert_to': converters.convert_to_boolean,
                      'is_visible': True,
                      'required_by_policy': True,
                      'enforce_policy': True},
        'ip_version': {'allow_post': True, 'allow_put': False,
                       'convert_to': converters.convert_to_int,
                       'validate': {'type:values': [4, 6]},
                       'is_visible': True},
    },
    subnetpool_def.COLLECTION_NAME: {
        ADDRESS_SCOPE_ID: {'allow_post': True,
                           'allow_put': True,
                           'default': constants.ATTR_NOT_SPECIFIED,
                           'validate': {'type:uuid_or_none': None},
                           'is_visible': True}
    },
    net_def.COLLECTION_NAME: {
        IPV4_ADDRESS_SCOPE: {'allow_post': False,
                             'allow_put': False,
                             'is_visible': True},
        IPV6_ADDRESS_SCOPE: {'allow_post': False,
                             'allow_put': False,
                             'is_visible': True},
    }
}


class AddressScopeNotFound(nexception.NotFound):
    message = _("Address scope %(address_scope_id)s could not be found")


class AddressScopeInUse(nexception.InUse):
    message = _("Unable to complete operation on "
                "address scope %(address_scope_id)s. There are one or more"
                " subnet pools in use on the address scope")


class AddressScopeUpdateError(nexception.BadRequest):
    message = _("Unable to update address scope %(address_scope_id)s : "
                "%(reason)s")


class Address_scope(api_extensions.ExtensionDescriptor):
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
        plugin = directory.get_plugin()
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
