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

from neutron_lib.api.definitions import address_group as apidef
from neutron_lib.api import extensions as api_extensions
from neutron_lib.plugins import directory

from neutron.api import extensions
from neutron.api.v2 import base


class Address_group(api_extensions.APIExtensionDescriptor):
    """Extension class supporting Address Groups."""
    api_definition = apidef

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plugin = directory.get_plugin()
        collection_name = apidef.COLLECTION_NAME.replace('_', '-')
        params = apidef.RESOURCE_ATTRIBUTE_MAP.get(
            apidef.COLLECTION_NAME, dict())
        controller = base.create_resource(collection_name,
                                          apidef.RESOURCE_NAME,
                                          plugin, params,
                                          member_actions=apidef.ACTION_MAP[
                                              apidef.RESOURCE_NAME],
                                          allow_bulk=True,
                                          allow_pagination=True,
                                          allow_sorting=True)

        ex = extensions.ResourceExtension(collection_name, controller,
                                          member_actions=apidef.ACTION_MAP[
                                              apidef.RESOURCE_NAME],
                                          attr_map=params)
        return [ex]


class AddressGroupPluginBase(object, metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def create_address_group(self, context, address_group):
        pass

    @abc.abstractmethod
    def update_address_group(self, context, id, address_group):
        pass

    @abc.abstractmethod
    def get_address_group(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def get_address_groups(self, context, filters=None, fields=None,
                           sorts=None, limit=None, marker=None,
                           page_reverse=False):
        pass

    @abc.abstractmethod
    def delete_address_group(self, context, id):
        pass

    @abc.abstractmethod
    def add_addresses(self, context, address_group_id, addresses):
        pass

    @abc.abstractmethod
    def remove_addresses(self, context, address_group_id, addresses):
        pass
