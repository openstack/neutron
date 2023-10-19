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
from neutron_lib.db import standard_attr
from neutron_lib import exceptions
from neutron_lib.plugins import directory
from neutron_lib import rpc as n_rpc
from neutron_lib.services import base as service_base
import webob.exc

from neutron._i18n import _
from neutron.api import extensions
from neutron.api.v2 import resource as api_resource
from neutron.objects import subnet
from neutron import policy


TAG = 'tag'
TAGS = TAG + 's'
TAGS_ANY = TAGS + '-any'
NOT_TAGS = 'not-' + TAGS
NOT_TAGS_ANY = NOT_TAGS + '-any'
MAX_TAG_LEN = 255
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
RESOURCES_AND_PARENTS = {'subnets': ('network', subnet.Subnet.get_network_id)}


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

    @staticmethod
    def _get_target(ctx, res_id, p_res, p_res_id, tag_id=None):
        target = {'id': res_id,
                  'tenant_id': ctx.project_id,
                  'project_id': ctx.project_id}
        if p_res:
            target[p_res + '_id'] = p_res_id
        if tag_id:
            target['tag_id'] = tag_id
        return target

    @staticmethod
    def _get_pparent_resource_and_id(context, resource, resource_id):
        """Retrieve the parent of the resource and ID (e.g.: subnet->net)"""
        parent, getter_id = RESOURCES_AND_PARENTS[resource]
        parent_id = getter_id(context.elevated(), resource_id)
        return parent, parent_id

    def _get_parent_resource_and_id(self, context, kwargs):
        parent, parent_id = None, None
        for key in kwargs:
            for resource in self.supported_resources:
                if key == self.supported_resources[resource] + '_id':
                    if resource in RESOURCES_AND_PARENTS.keys():
                        parent, parent_id = self._get_pparent_resource_and_id(
                            context, resource, kwargs[key])
                    return resource, kwargs[key], parent, parent_id
        return None, None, None, None

    def index(self, request, **kwargs):
        # GET /v2.0/{parent_resource}/{parent_resource_id}/tags
        ctx = request.context
        res, res_id, p_res, p_res_id = self._get_parent_resource_and_id(
            ctx, kwargs)
        target = self._get_target(ctx, res_id, p_res, p_res_id)
        policy.enforce(ctx, 'get_%s_%s' % (res, TAGS), target)
        return self.plugin.get_tags(ctx, res, res_id)

    def show(self, request, id, **kwargs):
        # GET /v2.0/{parent_resource}/{parent_resource_id}/tags/{tag}
        # id == tag
        validate_tag(id)
        ctx = request.context
        res, res_id, p_res, p_res_id = self._get_parent_resource_and_id(
            ctx, kwargs)
        target = self._get_target(ctx, res_id, p_res, p_res_id, tag_id=id)
        policy.enforce(ctx, 'get_%s_%s' % (res, TAGS), target)
        return self.plugin.get_tag(ctx, res, res_id, id)

    def create(self, request, **kwargs):
        # not supported
        # POST /v2.0/{parent_resource}/{parent_resource_id}/tags
        raise webob.exc.HTTPNotFound("not supported")

    def update(self, request, id, **kwargs):
        # PUT /v2.0/{parent_resource}/{parent_resource_id}/tags/{tag}
        # id == tag
        validate_tag(id)
        ctx = request.context
        res, res_id, p_res, p_res_id = self._get_parent_resource_and_id(
            ctx, kwargs)
        target = self._get_target(ctx, res_id, p_res, p_res_id, tag_id=id)
        policy.enforce(ctx, 'update_%s_%s' % (res, TAGS), target)
        notify_tag_action(ctx, 'create.start', res, res_id, [id])
        result = self.plugin.update_tag(ctx, res, res_id, id)
        notify_tag_action(ctx, 'create.end', res, res_id, [id])
        return result

    def update_all(self, request, body, **kwargs):
        # PUT /v2.0/{parent_resource}/{parent_resource_id}/tags
        # body: {"tags": ["aaa", "bbb"]}
        validate_tags(body)
        ctx = request.context
        res, res_id, p_res, p_res_id = self._get_parent_resource_and_id(
            ctx, kwargs)
        target = self._get_target(ctx, res_id, p_res, p_res_id)
        policy.enforce(ctx, 'update_%s_%s' % (res, TAGS), target)
        notify_tag_action(ctx, 'update.start', res, res_id, body['tags'])
        result = self.plugin.update_tags(ctx, res, res_id, body)
        notify_tag_action(ctx, 'update.end', res, res_id,
                          body['tags'])
        return result

    def delete(self, request, id, **kwargs):
        # DELETE /v2.0/{parent_resource}/{parent_resource_id}/tags/{tag}
        # id == tag
        validate_tag(id)
        ctx = request.context
        res, res_id, p_res, p_res_id = self._get_parent_resource_and_id(
            ctx, kwargs)
        target = self._get_target(ctx, res_id, p_res, p_res_id, tag_id=id)
        policy.enforce(ctx, 'delete_%s_%s' % (res, TAGS), target)
        notify_tag_action(ctx, 'delete.start', res, res_id, [id])
        result = self.plugin.delete_tag(ctx, res, res_id, id)
        notify_tag_action(ctx, 'delete.end', res, res_id, [id])
        return result

    def delete_all(self, request, **kwargs):
        # DELETE /v2.0/{parent_resource}/{parent_resource_id}/tags
        ctx = request.context
        res, res_id, p_res, p_res_id = self._get_parent_resource_and_id(
            ctx, kwargs)
        target = self._get_target(ctx, res_id, p_res, p_res_id)
        policy.enforce(ctx, 'delete_%s_%s' % (res, TAGS), target)
        notify_tag_action(ctx, 'delete_all.start', res, res_id)
        result = self.plugin.delete_tags(ctx, res, res_id)
        notify_tag_action(ctx, 'delete_all.end', res, res_id)
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
