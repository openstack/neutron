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

from neutron_lib.api import extensions as api_extensions
from neutron_lib.plugins import directory

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.api.v2 import base
from neutron.api.v2 import resource as api_resource
from neutron.extensions import l3
from neutron.extensions import tag as tag_base

TAG_SUPPORTED_RESOURCES = {
    # We shouldn't add new resources here. If more resources need to be tagged,
    # we must add them in new extension.
    attributes.SUBNETS: attributes.SUBNET,
    attributes.PORTS: attributes.PORT,
    attributes.SUBNETPOOLS: attributes.SUBNETPOOL,
    l3.ROUTERS: l3.ROUTER,
}


class TagExtController(tag_base.TagController):
    def __init__(self):
        self.plugin = directory.get_plugin(tag_base.TAG_PLUGIN_TYPE)
        self.supported_resources = TAG_SUPPORTED_RESOURCES


class Tag_ext(api_extensions.ExtensionDescriptor):
    """Extension class supporting tags for ext resources."""

    @classmethod
    def get_name(cls):
        return ("Tag support for resources: %s"
                % ', '.join(TAG_SUPPORTED_RESOURCES.values()))

    @classmethod
    def get_alias(cls):
        return "tag-ext"

    @classmethod
    def get_description(cls):
        return "Extends tag support to more L2 and L3 resources."

    @classmethod
    def get_updated(cls):
        return "2017-01-01T00:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        exts = []
        action_status = {'index': 200, 'show': 204, 'update': 201,
                         'update_all': 200, 'delete': 204, 'delete_all': 204}
        controller = api_resource.Resource(TagExtController(),
                                           base.FAULT_MAP,
                                           action_status=action_status)
        collection_methods = {"delete_all": "DELETE",
                              "update_all": "PUT"}
        exts = []
        for collection_name, member_name in TAG_SUPPORTED_RESOURCES.items():
            parent = {'member_name': member_name,
                      'collection_name': collection_name}
            exts.append(extensions.ResourceExtension(
                tag_base.TAGS, controller, parent,
                collection_methods=collection_methods))
        return exts

    def get_optional_extensions(self):
        return ['router']

    def get_extended_resources(self, version):
        if version != "2.0":
            return {}
        EXTENDED_ATTRIBUTES_2_0 = {}
        for collection_name in TAG_SUPPORTED_RESOURCES:
            EXTENDED_ATTRIBUTES_2_0[collection_name] = (
                tag_base.TAG_ATTRIBUTE_MAP)
        return EXTENDED_ATTRIBUTES_2_0
