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

from neutron_lib.api.definitions import portbindings_extended as pbe_ext
from neutron_lib.api import extensions as api_extensions
from neutron_lib.plugins import directory

from neutron.api import extensions
from neutron.api.v2 import base

EXT_ALIAS = pbe_ext.ALIAS


class Portbindings_extended(api_extensions.ExtensionDescriptor):
    """Extension class supporting port bindings.

    This class is used by neutron's extension framework to make
    metadata about the port bindings available to external applications.

    With admin rights one will be able to update and read the values.
    """
    @classmethod
    def get_name(cls):
        return pbe_ext.NAME

    @classmethod
    def get_alias(cls):
        return pbe_ext.ALIAS

    @classmethod
    def get_description(cls):
        return pbe_ext.DESCRIPTION

    @classmethod
    def get_updated(cls):
        return pbe_ext.UPDATED_TIMESTAMP

    @classmethod
    def get_resources(cls):
        plugin = directory.get_plugin()

        params = pbe_ext.SUB_RESOURCE_ATTRIBUTE_MAP[
            pbe_ext.COLLECTION_NAME]['parameters']
        parent = pbe_ext.SUB_RESOURCE_ATTRIBUTE_MAP[
            pbe_ext.COLLECTION_NAME]['parent']
        controller = base.create_resource(
            pbe_ext.COLLECTION_NAME,
            pbe_ext.RESOURCE_NAME,
            plugin,
            params,
            member_actions=pbe_ext.ACTION_MAP[pbe_ext.RESOURCE_NAME],
            parent=parent,
            allow_pagination=True,
            allow_sorting=True,
        )
        exts = [
            extensions.ResourceExtension(
                pbe_ext.COLLECTION_NAME,
                controller,
                parent,
                member_actions=pbe_ext.ACTION_MAP[pbe_ext.RESOURCE_NAME],
                attr_map=params,
            ),
        ]

        return exts
