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
import copy

from neutron_lib.api.definitions import port
from neutron_lib.api import extensions as api_extensions
from neutron_lib.api import faults
from neutron_lib.api import validators
from neutron_lib import exceptions
from neutron_lib.plugins import directory
from neutron_lib import rpc as n_rpc
from neutron_lib.services import base as service_base
import webob.exc

from neutron._i18n import _
from neutron.api import extensions
from neutron.api.v2 import resource as api_resource
from neutron.db import standard_attr


TAG = 'tag'
TAGS = TAG + 's'
TAGS_ANY = TAGS + '-any'
NOT_TAGS = 'not-' + TAGS
NOT_TAGS_ANY = NOT_TAGS + '-any'
MAX_TAG_LEN = 60
TAG_PLUGIN_TYPE = 'TAG'

TAG_SUPPORTED_RESOURCES = standard_attr.get_tag_resource_parent_map()
TAG_ATTRIBUTE_MAP = {
    TAGS: {'allow_post': False, 'allow_put': False,
           'is_visible': True, 'is_filter': True},
    TAGS_ANY: {'allow_post': False, 'allow_put': False,
               'is_visible': False, 'is_filter': True},
    NOT_TAGS: {'allow_post': False, 'allow_put': False,
               'is_visible': False, 'is_filter': True},
    NOT_TAGS_ANY: {'allow_post': False, 'allow_put': False,
                   'is_visible': False, 'is_filter': True},
}
TAG_ATTRIBUTE_MAP_PORTS = copy.deepcopy(TAG_ATTRIBUTE_MAP)
TAG_ATTRIBUTE_MAP_PORTS[TAGS] = {
        'allow_post': True, 'allow_put': False,
        'validate': {'type:list_of_unique_strings': MAX_TAG_LEN},
        'default': [], 'is_visible': True, 'is_filter': True
}


class TagResourceNotFound(exceptions.NotFound):
    message = _("Resource %(resource)s %(resource_id)s could not be found.")


class TagNotFound(exceptions.NotFound):
    message = _("Tag %(tag)s could not be found.")


def validate_tag(tag):
    msg = validators.validate_string(tag, MAX_TAG_LEN)
    if msg:
        raise exceptions.InvalidInput(error_message=msg)


def validate_tags(body):
    if not isinstance(body, dict) or 'tags' not in body:
        raise exceptions.InvalidInput(error_message=_("Invalid tags body"))
    msg = validators.validate_list_of_unique_strings(body['tags'], MAX_TAG_LEN)
    if msg:
        raise exceptions.InvalidInput(error_message=msg)


def notify_tag_action(context, action, parent, parent_id, tags=None):
    notifier = n_rpc.get_notifier('network')
    tag_event = 'tag.%s' % action
    # TODO(hichihara): Add 'updated_at' into payload
    payload = {'parent_resource': parent,
               'parent_resource_id': parent_id}
    if tags is not None:
        payload['tags'] = tags
    notifier.info(context, tag_event, payload)


class TaggingController(object):
    def __init__(self):
        self.plugin = directory.get_plugin(TAG_PLUGIN_TYPE)
        self.supported_resources = TAG_SUPPORTED_RESOURCES

    def _get_parent_resource_and_id(self, kwargs):
        for key in kwargs:
            for resource in self.supported_resources:
                if key == self.supported_resources[resource] + '_id':
                    return resource, kwargs[key]
        return None, None

    def index(self, request, **kwargs):
        # GET /v2.0/networks/{network_id}/tags
        parent, parent_id = self._get_parent_resource_and_id(kwargs)
        return self.plugin.get_tags(request.context, parent, parent_id)

    def show(self, request, id, **kwargs):
        # GET /v2.0/networks/{network_id}/tags/{tag}
        # id == tag
        validate_tag(id)
        parent, parent_id = self._get_parent_resource_and_id(kwargs)
        return self.plugin.get_tag(request.context, parent, parent_id, id)

    def create(self, request, **kwargs):
        # not supported
        # POST /v2.0/networks/{network_id}/tags
        raise webob.exc.HTTPNotFound("not supported")

    def update(self, request, id, **kwargs):
        # PUT /v2.0/networks/{network_id}/tags/{tag}
        # id == tag
        validate_tag(id)
        parent, parent_id = self._get_parent_resource_and_id(kwargs)
        notify_tag_action(request.context, 'create.start',
                          parent, parent_id, [id])
        result = self.plugin.update_tag(request.context, parent, parent_id, id)
        notify_tag_action(request.context, 'create.end',
                          parent, parent_id, [id])
        return result

    def update_all(self, request, body, **kwargs):
        # PUT /v2.0/networks/{network_id}/tags
        # body: {"tags": ["aaa", "bbb"]}
        validate_tags(body)
        parent, parent_id = self._get_parent_resource_and_id(kwargs)
        notify_tag_action(request.context, 'update.start',
                          parent, parent_id, body['tags'])
        result = self.plugin.update_tags(request.context, parent,
                                         parent_id, body)
        notify_tag_action(request.context, 'update.end',
                          parent, parent_id, body['tags'])
        return result

    def delete(self, request, id, **kwargs):
        # DELETE /v2.0/networks/{network_id}/tags/{tag}
        # id == tag
        validate_tag(id)
        parent, parent_id = self._get_parent_resource_and_id(kwargs)
        notify_tag_action(request.context, 'delete.start',
                          parent, parent_id, [id])
        result = self.plugin.delete_tag(request.context, parent, parent_id, id)
        notify_tag_action(request.context, 'delete.end',
                          parent, parent_id, [id])
        return result

    def delete_all(self, request, **kwargs):
        # DELETE /v2.0/networks/{network_id}/tags
        parent, parent_id = self._get_parent_resource_and_id(kwargs)
        notify_tag_action(request.context, 'delete_all.start',
                          parent, parent_id)
        result = self.plugin.delete_tags(request.context, parent, parent_id)
        notify_tag_action(request.context, 'delete_all.end',
                          parent, parent_id)
        return result


class Tagging(api_extensions.ExtensionDescriptor):
    """Extension class supporting tags."""

    @classmethod
    def get_name(cls):
        return ("Tag support for resources with standard attribute: %s"
                % ', '.join(TAG_SUPPORTED_RESOURCES.values()))

    @classmethod
    def get_alias(cls):
        return "standard-attr-tag"

    @classmethod
    def get_description(cls):
        return "Enables to set tag on resources with standard attribute."

    @classmethod
    def get_updated(cls):
        return "2017-01-01T00:00:00-00:00"

    def get_required_extensions(self):
        return []

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        exts = []
        action_status = {'index': 200, 'show': 204, 'update': 201,
                         'update_all': 200, 'delete': 204, 'delete_all': 204}
        controller = api_resource.Resource(TaggingController(),
                                           faults.FAULT_MAP,
                                           action_status=action_status)
        collection_methods = {"delete_all": "DELETE",
                              "update_all": "PUT"}
        exts = []
        for collection_name, member_name in TAG_SUPPORTED_RESOURCES.items():
            if 'security_group' in collection_name:
                collection_name = collection_name.replace('_', '-')
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
            if collection_name == port.COLLECTION_NAME:
                EXTENDED_ATTRIBUTES_2_0[collection_name] = (
                    TAG_ATTRIBUTE_MAP_PORTS)
            else:
                EXTENDED_ATTRIBUTES_2_0[collection_name] = TAG_ATTRIBUTE_MAP
        return EXTENDED_ATTRIBUTES_2_0


class TagPluginBase(service_base.ServicePluginBase, metaclass=abc.ABCMeta):
    """REST API to operate the Tag."""

    def get_plugin_description(self):
        return "Tag support"

    @classmethod
    def get_plugin_type(cls):
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
