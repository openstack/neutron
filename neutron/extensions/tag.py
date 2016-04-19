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

from neutron_lib.api import validators
from neutron_lib import exceptions
from oslo_log import log as logging
import six
import webob.exc

from neutron._i18n import _
from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.api.v2 import base
from neutron.api.v2 import resource as api_resource
from neutron import manager
from neutron.services import service_base


LOG = logging.getLogger(__name__)

TAG = 'tag'
TAGS = TAG + 's'
MAX_TAG_LEN = 60
TAG_PLUGIN_TYPE = 'TAG'

TAG_SUPPORTED_RESOURCES = {
    attributes.NETWORKS: attributes.NETWORK,
    # other resources can be added
}

TAG_ATTRIBUTE_MAP = {
    TAGS: {'allow_post': False, 'allow_put': False, 'is_visible': True}
}


class TagResourceNotFound(exceptions.NotFound):
    message = _("Resource %(resource)s %(resource_id)s could not be found.")


class TagNotFound(exceptions.NotFound):
    message = _("Tag %(tag)s could not be found.")


def get_parent_resource_and_id(kwargs):
    for key in kwargs:
        for resource in TAG_SUPPORTED_RESOURCES:
            if key == TAG_SUPPORTED_RESOURCES[resource] + '_id':
                return resource, kwargs[key]
    return None, None


def validate_tag(tag):
    msg = validators.validate_string(tag, MAX_TAG_LEN)
    if msg:
        raise exceptions.InvalidInput(error_message=msg)


def validate_tags(body):
    if 'tags' not in body:
        raise exceptions.InvalidInput(error_message="Invalid tags body.")
    msg = validators.validate_list_of_unique_strings(body['tags'], MAX_TAG_LEN)
    if msg:
        raise exceptions.InvalidInput(error_message=msg)


class TagController(object):
    def __init__(self):
        self.plugin = (manager.NeutronManager.get_service_plugins()
                       [TAG_PLUGIN_TYPE])

    def index(self, request, **kwargs):
        # GET /v2.0/networks/{network_id}/tags
        parent, parent_id = get_parent_resource_and_id(kwargs)
        return self.plugin.get_tags(request.context, parent, parent_id)

    def show(self, request, id, **kwargs):
        # GET /v2.0/networks/{network_id}/tags/{tag}
        # id == tag
        validate_tag(id)
        parent, parent_id = get_parent_resource_and_id(kwargs)
        return self.plugin.get_tag(request.context, parent, parent_id, id)

    def create(self, request, **kwargs):
        # not supported
        # POST /v2.0/networks/{network_id}/tags
        raise webob.exc.HTTPNotFound("not supported")

    def update(self, request, id, **kwargs):
        # PUT /v2.0/networks/{network_id}/tags/{tag}
        # id == tag
        validate_tag(id)
        parent, parent_id = get_parent_resource_and_id(kwargs)
        return self.plugin.update_tag(request.context, parent, parent_id, id)

    def update_all(self, request, body, **kwargs):
        # PUT /v2.0/networks/{network_id}/tags
        # body: {"tags": ["aaa", "bbb"]}
        validate_tags(body)
        parent, parent_id = get_parent_resource_and_id(kwargs)
        return self.plugin.update_tags(request.context, parent, parent_id,
                                       body)

    def delete(self, request, id, **kwargs):
        # DELETE /v2.0/networks/{network_id}/tags/{tag}
        # id == tag
        validate_tag(id)
        parent, parent_id = get_parent_resource_and_id(kwargs)
        return self.plugin.delete_tag(request.context, parent, parent_id, id)

    def delete_all(self, request, **kwargs):
        # DELETE /v2.0/networks/{network_id}/tags
        parent, parent_id = get_parent_resource_and_id(kwargs)
        return self.plugin.delete_tags(request.context, parent, parent_id)


class Tag(extensions.ExtensionDescriptor):
    """Extension class supporting tags."""

    @classmethod
    def get_name(cls):
        return "Tag support"

    @classmethod
    def get_alias(cls):
        return "tag"

    @classmethod
    def get_description(cls):
        return "Enables to set tag on resources."

    @classmethod
    def get_updated(cls):
        return "2016-01-01T00:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        exts = []
        action_status = {'index': 200, 'show': 204, 'update': 201,
                         'update_all': 200, 'delete': 204, 'delete_all': 204}
        controller = api_resource.Resource(TagController(),
                                           base.FAULT_MAP,
                                           action_status=action_status)
        collection_methods = {"delete_all": "DELETE",
                              "update_all": "PUT"}
        exts = []
        for collection_name, member_name in TAG_SUPPORTED_RESOURCES.items():
            parent = {'member_name': member_name,
                      'collection_name': collection_name}
            exts.append(extensions.ResourceExtension(
                TAGS, controller, parent,
                collection_methods=collection_methods))
        return exts

    def get_extended_resources(self, version):
        if version != "2.0":
            return {}
        EXTENDED_ATTRIBUTES_2_0 = {}
        for collection_name in TAG_SUPPORTED_RESOURCES:
            EXTENDED_ATTRIBUTES_2_0[collection_name] = TAG_ATTRIBUTE_MAP
        return EXTENDED_ATTRIBUTES_2_0


@six.add_metaclass(abc.ABCMeta)
class TagPluginBase(service_base.ServicePluginBase):
    """REST API to operate the Tag."""

    def get_plugin_description(self):
        return "Tag support"

    def get_plugin_type(self):
        return TAG_PLUGIN_TYPE

    @abc.abstractmethod
    def get_tags(self, context, resource, resource_id):
        pass

    @abc.abstractmethod
    def get_tag(self, context, resource, resource_id, tag):
        pass

    @abc.abstractmethod
    def update_tags(self, context, resource, resource_id, body):
        pass

    @abc.abstractmethod
    def update_tag(self, context, resource, resource_id, tag):
        pass

    @abc.abstractmethod
    def delete_tags(self, context, resource, resource_id):
        pass

    @abc.abstractmethod
    def delete_tag(self, context, resource, resource_id, tag):
        pass
