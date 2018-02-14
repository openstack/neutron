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

from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api.definitions import port as port_def
from neutron_lib.api.definitions import subnet as subnet_def
from neutron_lib.api.definitions import subnetpool as subnetpool_def
from neutron_lib.api import extensions as api_extensions
from neutron_lib.api import faults
from neutron_lib.plugins import directory

from neutron.api import extensions
from neutron.api.v2 import resource as api_resource
from neutron.extensions import tagging


# This extension is deprecated because tagging supports all resources

TAG_SUPPORTED_RESOURCES = {
    # We shouldn't add new resources here. If more resources need to be tagged,
    # we must add them in new extension.
    subnet_def.COLLECTION_NAME: subnet_def.RESOURCE_NAME,
    port_def.COLLECTION_NAME: port_def.RESOURCE_NAME,
    subnetpool_def.COLLECTION_NAME: subnetpool_def.RESOURCE_NAME,
    l3_apidef.ROUTERS: l3_apidef.ROUTER,
}


class TagExtController(tagging.TaggingController):
    def __init__(self):
        self.plugin = directory.get_plugin(tagging.TAG_PLUGIN_TYPE)
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
                                           faults.FAULT_MAP,
                                           action_status=action_status)
        collection_methods = {"delete_all": "DELETE",
                              "update_all": "PUT"}
        exts = []
        for collection_name, member_name in TAG_SUPPORTED_RESOURCES.items():
            parent = {'member_name': member_name,
                      'collection_name': collection_name}
            exts.append(extensions.ResourceExtension(
                tagging.TAGS, controller, parent,
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
                tagging.TAG_ATTRIBUTE_MAP)
        return EXTENDED_ATTRIBUTES_2_0
