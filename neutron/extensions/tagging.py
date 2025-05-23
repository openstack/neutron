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
import collections
import copy
import itertools
import typing

from neutron_lib.api import attributes
from neutron_lib.api.definitions import port
from neutron_lib.api import extensions as api_extensions
from neutron_lib.api import faults
from neutron_lib.api import validators
from neutron_lib import constants
from neutron_lib.db import standard_attr
from neutron_lib import exceptions
from neutron_lib.plugins import directory
from neutron_lib import rpc as n_rpc
from neutron_lib.services import base as service_base

from neutron._i18n import _
from neutron.api import extensions
from neutron.api.v2 import resource as api_resource
from neutron.objects import network as network_obj
from neutron.objects import network_segment_range as network_segment_range_obj
from neutron.objects import ports as ports_obj
from neutron.objects.qos import policy as policy_obj
from neutron.objects import router as router_obj
from neutron.objects import securitygroup as securitygroup_obj
from neutron.objects import subnet as subnet_obj
from neutron.objects import subnetpool as subnetpool_obj
from neutron.objects import trunk as trunk_obj
from neutron import policy


TAG = 'tag'
TAGS = TAG + 's'
TAGS_ANY = TAGS + '-any'
NOT_TAGS = 'not-' + TAGS
NOT_TAGS_ANY = NOT_TAGS + '-any'
MAX_TAG_LEN = 255
MAX_TAGS_COUNT = 50
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

TAG_ATTRIBUTE_MAP_PORTS: dict[str, typing.Any]
TAG_ATTRIBUTE_MAP_PORTS = copy.deepcopy(TAG_ATTRIBUTE_MAP)
TAG_ATTRIBUTE_MAP_PORTS[TAGS] = {
        'allow_post': True, 'allow_put': False,
        'validate': {'type:list_of_unique_strings': MAX_TAG_LEN},
        'default': [], 'is_visible': True, 'is_filter': True
}
OVO_CLS = {
    'floatingips': router_obj.FloatingIP,
    'network_segment_ranges': network_segment_range_obj.NetworkSegmentRange,
    'networks': network_obj.Network,
    'policies': policy_obj.QosPolicy,
    'ports': ports_obj.Port,
    'routers': router_obj.Router,
    'security_groups': securitygroup_obj.SecurityGroup,
    'subnets': subnet_obj.Subnet,
    'subnetpools': subnetpool_obj.SubnetPool,
    'trunks': trunk_obj.Trunk,
}
ResourceInfo = collections.namedtuple(
    'ResourceInfo', ['project_id',
                     'obj_type',
                     'obj',
                     ])
EMPTY_RESOURCE_INFO = ResourceInfo(None, None, None)


class TagResourceNotFound(exceptions.NotFound):
    message = _("Resource %(resource)s %(resource_id)s could not be found.")


class TagNotFound(exceptions.NotFound):
    message = _("Tag %(tag)s could not be found.")


def validate_tag(tag):
    msg = validators.validate_string(tag, MAX_TAG_LEN)
    if msg:
        raise exceptions.InvalidInput(error_message=msg)


def validate_tags_limit(resource, tags):
    tags = set(tags)
    if len(tags) > MAX_TAGS_COUNT:
        msg = (_("The number of tags exceed the per-resource limit of %d")
               % MAX_TAGS_COUNT)
        raise exceptions.BadRequest(resource=resource, msg=msg)


def validate_tags(body):
    if not isinstance(body, dict) or 'tags' not in body:
        raise exceptions.InvalidInput(error_message=_("Invalid tags body"))
    msg = validators.validate_list_of_unique_strings(body['tags'], MAX_TAG_LEN)
    if msg:
        raise exceptions.InvalidInput(error_message=msg)


def notify_tag_action(context, action, obj, obj_id, tags=None):
    notifier = n_rpc.get_notifier('network')
    tag_event = 'tag.%s' % action
    # TODO(hichihara): Add 'updated_at' into payload
    payload = {'obj_resource': obj,
               'obj_resource_id': obj_id}
    if tags is not None:
        payload['tags'] = tags
    notifier.info(context, tag_event, payload)


class TaggingController:
    def __init__(self):
        self.plugin = directory.get_plugin(TAG_PLUGIN_TYPE)
        self.supported_resources = TAG_SUPPORTED_RESOURCES

    def _get_resource_info(self, context, kwargs, tags=None):
        """Return the information about the resource with the tag(s)

        :param kwargs: dictionary with the resource ID, along with other
                       information. It is formated as
                       {"resource_id": "id", ...}
        :param tags: list of the tags which will be set for the resource
        :return: ``ResourceInfo`` named tuple with the object's type,
                 object's information in the dict and the project ID
        """
        for key, obj_type in itertools.product(
                kwargs.keys(), self.supported_resources.keys()):
            if key != self.supported_resources[obj_type] + '_id':
                continue

            obj_id = kwargs[key]
            obj_class = OVO_CLS[obj_type]
            try:
                field_list = []
                for attr_name, attr_config in \
                        attributes.RESOURCES[obj_type].items():
                    if (attr_config.get('required_by_policy') or
                            attr_config.get('primary_key') or
                            'default' not in attr_config):
                        field_list.append(attr_name)
                obj_dict = {
                    constants.ATTRIBUTES_TO_UPDATE: [TAGS]
                }
                if tags is not None:
                    obj_dict[TAGS] = tags
                obj = obj_class.get_object(context.elevated(), id=obj_id,
                                           fields=field_list)
                if not obj:
                    return EMPTY_RESOURCE_INFO
                for f_name, f_value in obj.to_dict().items():
                    if f_name in field_list:
                        obj_dict[f_name] = f_value
                project_id = obj_dict.get('project_id')
                if not project_id:
                    project_id = obj_dict.get('tenant_id')
                    obj_dict['project_id'] = project_id
            except IndexError:
                return EMPTY_RESOURCE_INFO

            return ResourceInfo(project_id, obj_type, obj_dict)

        # This should never be returned.
        return EMPTY_RESOURCE_INFO

    def _get_policy_action(self, base_action, obj_type):
        return "{}_{}:{}".format(
            base_action,
            self.supported_resources[obj_type],
            TAGS)

    def index(self, request, **kwargs):
        # GET /v2.0/{obj_resource}/{obj_resource_id}/tags
        ctx = request.context
        rinfo = self._get_resource_info(ctx, kwargs)
        policy.enforce(ctx, f'get_{rinfo.obj_type}_{TAGS}',
                       rinfo.obj)
        return self.plugin.get_tags(ctx, rinfo.obj_type, rinfo.obj['id'])

    def show(self, request, id, **kwargs):
        # GET /v2.0/{obj_resource}/{obj_resource_id}/tags/{tag}
        # id == tag
        validate_tag(id)
        ctx = request.context
        rinfo = self._get_resource_info(ctx, kwargs)
        policy.enforce(ctx, f'get_{rinfo.obj_type}:{TAGS}',
                       rinfo.obj)
        return self.plugin.get_tag(ctx, rinfo.obj_type, rinfo.obj['id'], id)

    def create(self, request, body, **kwargs):
        # POST /v2.0/{obj_resource}/{obj_resource_id}/tags
        # body: {"tags": ["aaa", "bbb"]}
        validate_tags(body)
        ctx = request.context
        rinfo = self._get_resource_info(ctx, kwargs, tags=body[TAGS])
        policy.enforce(ctx, f'create_{rinfo.obj_type}:{TAGS}',
                       rinfo.obj)
        validate_tags_limit(rinfo.obj_type, body['tags'])
        notify_tag_action(ctx, 'create.start', rinfo.obj_type,
                          rinfo.obj['id'], body['tags'])
        result = self.plugin.create_tags(ctx, rinfo.obj_type,
                                         rinfo.obj['id'], body)
        notify_tag_action(ctx, 'create.end', rinfo.obj_type,
                          rinfo.obj['id'], body['tags'])
        return result

    def update(self, request, id, **kwargs):
        # PUT /v2.0/{obj_resource}/{obj_resource_id}/tags/{tag}
        # id == tag
        validate_tag(id)
        ctx = request.context
        rinfo = self._get_resource_info(ctx, kwargs, tags=[id])
        policy.enforce(ctx, f'update_{rinfo.obj_type}:{TAGS}',
                       rinfo.obj)
        current_tags = self.plugin.get_tags(
            ctx, rinfo.obj_type, rinfo.obj['id'])['tags']
        new_tags = current_tags + [id]
        validate_tags_limit(rinfo.obj_type, new_tags)
        notify_tag_action(ctx, 'create.start', rinfo.obj_type,
                          rinfo.obj['id'], [id])
        result = self.plugin.update_tag(ctx, rinfo.obj_type,
                                        rinfo.obj['id'], id)
        notify_tag_action(ctx, 'create.end', rinfo.obj_type,
                          rinfo.obj['id'], [id])
        return result

    def update_all(self, request, body, **kwargs):
        # PUT /v2.0/{obj_resource}/{obj_resource_id}/tags
        # body: {"tags": ["aaa", "bbb"]}
        validate_tags(body)
        ctx = request.context
        rinfo = self._get_resource_info(ctx, kwargs, tags=body[TAGS])
        policy.enforce(
            ctx,
            self._get_policy_action("update", rinfo.obj_type),
            rinfo.obj)
        validate_tags_limit(rinfo.obj_type, body['tags'])
        notify_tag_action(ctx, 'update.start', rinfo.obj_type,
                          rinfo.obj['id'], body['tags'])
        result = self.plugin.update_tags(ctx, rinfo.obj_type,
                                         rinfo.obj['id'], body)
        notify_tag_action(ctx, 'update.end', rinfo.obj_type,
                          rinfo.obj['id'], body['tags'])
        return result

    def delete(self, request, id, **kwargs):
        # DELETE /v2.0/{obj_resource}/{obj_resource_id}/tags/{tag}
        # id == tag
        validate_tag(id)
        ctx = request.context
        rinfo = self._get_resource_info(ctx, kwargs)
        policy.enforce(
            ctx,
            self._get_policy_action("delete", rinfo.obj_type),
            rinfo.obj)
        notify_tag_action(ctx, 'delete.start', rinfo.obj_type,
                          rinfo.obj['id'], [id])
        result = self.plugin.delete_tag(ctx, rinfo.obj_type,
                                        rinfo.obj['id'], id)
        notify_tag_action(ctx, 'delete.end', rinfo.obj_type,
                          rinfo.obj['id'], [id])
        return result

    def delete_all(self, request, **kwargs):
        # DELETE /v2.0/{obj_resource}/{obj_resource_id}/tags
        ctx = request.context
        rinfo = self._get_resource_info(ctx, kwargs)
        policy.enforce(
            ctx,
            self._get_policy_action("delete", rinfo.obj_type),
            rinfo.obj)
        notify_tag_action(ctx, 'delete_all.start', rinfo.obj_type,
                          rinfo.obj['id'])
        result = self.plugin.delete_tags(ctx, rinfo.obj_type,
                                         rinfo.obj['id'])
        notify_tag_action(ctx, 'delete_all.end', rinfo.obj_type,
                          rinfo.obj['id'])
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
            obj = {'member_name': member_name,
                   'collection_name': collection_name}
            exts.append(extensions.ResourceExtension(
                TAGS, controller, obj,
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
