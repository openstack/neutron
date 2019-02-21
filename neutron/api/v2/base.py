# Copyright (c) 2012 OpenStack Foundation.
# All Rights Reserved.
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

import collections
import copy

from neutron_lib.api import attributes
from neutron_lib.api import faults
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.db import api as db_api
from neutron_lib import exceptions
from neutron_lib import rpc as n_rpc
from oslo_log import log as logging
from oslo_policy import policy as oslo_policy
from oslo_utils import excutils
import webob.exc

from neutron._i18n import _
from neutron.api import api_common
from neutron.api.v2 import resource as wsgi_resource
from neutron.common import constants as n_const
from neutron import policy
from neutron import quota
from neutron.quota import resource_registry


LOG = logging.getLogger(__name__)


class Controller(object):
    LIST = 'list'
    SHOW = 'show'
    CREATE = 'create'
    UPDATE = 'update'
    DELETE = 'delete'

    @property
    def plugin(self):
        return self._plugin

    @property
    def resource(self):
        return self._resource

    @property
    def attr_info(self):
        return self._attr_info

    @property
    def member_actions(self):
        return self._member_actions

    @property
    def allow_pagination(self):
        return self._allow_pagination

    @property
    def allow_sorting(self):
        return self._allow_sorting

    def _init_policy_attrs(self):
        """Create the list of attributes required by policy.

        If the attribute map contains a tenant_id policy, then include
        project_id to bring the resource into the brave new world.

        :return: sorted list of attributes required by policy

        """
        policy_attrs = {name for (name, info) in self._attr_info.items()
                        if info.get('required_by_policy')}
        if 'tenant_id' in policy_attrs:
            policy_attrs.add('project_id')

        # Could use list(), but sorted() makes testing easier.
        return sorted(policy_attrs)

    def __init__(self, plugin, collection, resource, attr_info,
                 allow_bulk=False, member_actions=None, parent=None,
                 allow_pagination=False, allow_sorting=False):
        if member_actions is None:
            member_actions = []
        self._plugin = plugin
        self._collection = collection.replace('-', '_')
        self._resource = resource.replace('-', '_')
        self._attr_info = attr_info
        self._allow_bulk = allow_bulk
        self._allow_pagination = allow_pagination
        self._allow_sorting = allow_sorting
        self._native_bulk = self._is_native_bulk_supported()
        self._native_pagination = self._is_native_pagination_supported()
        self._native_sorting = self._is_native_sorting_supported()
        self._filter_validation = self._is_filter_validation_supported()
        self._policy_attrs = self._init_policy_attrs()
        self._notifier = n_rpc.get_notifier('network')
        self._member_actions = member_actions
        self._primary_key = self._get_primary_key()
        if self._allow_pagination and self._native_pagination:
            # Native pagination need native sorting support
            if not self._native_sorting:
                raise exceptions.Invalid(
                    _("Native pagination depend on native sorting")
                )
            if not self._allow_sorting:
                LOG.info("Allow sorting is enabled because native "
                         "pagination requires native sorting")
                self._allow_sorting = True
        self.parent = parent
        if parent:
            self._parent_id_name = '%s_id' % parent['member_name']
            parent_part = '_%s' % parent['member_name']
        else:
            self._parent_id_name = None
            parent_part = ''
        self._plugin_handlers = {
            self.LIST: 'get%s_%s' % (parent_part, self._collection),
            self.SHOW: 'get%s_%s' % (parent_part, self._resource)
        }
        for action in [self.CREATE, self.UPDATE, self.DELETE]:
            self._plugin_handlers[action] = '%s%s_%s' % (action, parent_part,
                                                         self._resource)

    def _get_primary_key(self, default_primary_key='id'):
        for key, value in self._attr_info.items():
            if value.get('primary_key', False):
                return key
        return default_primary_key

    def _is_native_bulk_supported(self):
        native_bulk_attr_name = ("_%s__native_bulk_support"
                                 % self._plugin.__class__.__name__)
        return getattr(self._plugin, native_bulk_attr_name, False)

    def _is_native_pagination_supported(self):
        return api_common.is_native_pagination_supported(self._plugin)

    def _is_native_sorting_supported(self):
        return api_common.is_native_sorting_supported(self._plugin)

    def _is_filter_validation_supported(self):
        return api_common.is_filter_validation_supported(self._plugin)

    def _exclude_attributes_by_policy(self, context, data):
        """Identifies attributes to exclude according to authZ policies.

        Return a list of attribute names which should be stripped from the
        response returned to the user because the user is not authorized
        to see them.
        """
        attributes_to_exclude = []
        for attr_name in data.keys():
            # TODO(amotoki): At now, all attribute maps have tenant_id and
            # determine excluded attributes based on tenant_id.
            # We need to migrate tenant_id to project_id later
            # as attr_info is referred to in various places and we need
            # to check all logis carefully.
            if attr_name == 'project_id':
                continue
            attr_data = self._attr_info.get(attr_name)
            if attr_data and attr_data['is_visible']:
                if policy.check(
                        context,
                        '%s:%s' % (self._plugin_handlers[self.SHOW],
                                   attr_name),
                        data,
                        might_not_exist=True,
                        pluralized=self._collection):
                    # this attribute is visible, check next one
                    continue
            # if the code reaches this point then either the policy check
            # failed or the attribute was not visible in the first place
            attributes_to_exclude.append(attr_name)
            # TODO(amotoki): As mentioned in the above TODO,
            # we treat project_id and tenant_id equivalently.
            # This should be migrated to project_id in Ocata.
            if attr_name == 'tenant_id':
                attributes_to_exclude.append('project_id')

        return attributes_to_exclude

    def _view(self, context, data, fields_to_strip=None):
        """Build a view of an API resource.

        :param context: the neutron context
        :param data: the object for which a view is being created
        :param fields_to_strip: attributes to remove from the view

        :returns: a view of the object which includes only attributes
        visible according to API resource declaration and authZ policies.
        """
        fields_to_strip = ((fields_to_strip or []) +
                           self._exclude_attributes_by_policy(context, data))
        return self._filter_attributes(data, fields_to_strip)

    def _filter_attributes(self, data, fields_to_strip=None):
        if not fields_to_strip:
            return data
        return dict(item for item in data.items()
                    if (item[0] not in fields_to_strip))

    def _do_field_list(self, original_fields):
        fields_to_add = None
        # don't do anything if fields were not specified in the request
        if original_fields:
            fields_to_add = [attr for attr in self._policy_attrs
                             if attr not in original_fields]
            original_fields.extend(self._policy_attrs)
        return original_fields, fields_to_add

    def __getattr__(self, name):
        if name in self._member_actions:
            @db_api.retry_db_errors
            def _handle_action(request, id, **kwargs):
                arg_list = [request.context, id]
                # Ensure policy engine is initialized
                policy.init()
                # Fetch the resource and verify if the user can access it
                try:
                    parent_id = kwargs.get(self._parent_id_name)
                    resource = self._item(request,
                                          id,
                                          do_authz=True,
                                          field_list=None,
                                          parent_id=parent_id)
                except oslo_policy.PolicyNotAuthorized:
                    msg = _('The resource could not be found.')
                    raise webob.exc.HTTPNotFound(msg)
                body = kwargs.pop('body', None)
                # Explicit comparison with None to distinguish from {}
                if body is not None:
                    arg_list.append(body)
                # It is ok to raise a 403 because accessibility to the
                # object was checked earlier in this method
                policy.enforce(request.context,
                               name,
                               resource,
                               pluralized=self._collection)
                ret_value = getattr(self._plugin, name)(*arg_list, **kwargs)
                # It is simply impossible to predict whether one of this
                # actions alters resource usage. For instance a tenant port
                # is created when a router interface is added. Therefore it is
                # important to mark as dirty resources whose counters have
                # been altered by this operation
                resource_registry.set_resources_dirty(request.context)
                return ret_value

            return _handle_action
        else:
            raise AttributeError()

    def _get_pagination_helper(self, request):
        if self._allow_pagination and self._native_pagination:
            return api_common.PaginationNativeHelper(request,
                                                     self._primary_key)
        elif self._allow_pagination:
            return api_common.PaginationEmulatedHelper(request,
                                                       self._primary_key)
        return api_common.NoPaginationHelper(request, self._primary_key)

    def _get_sorting_helper(self, request):
        if self._allow_sorting and self._native_sorting:
            return api_common.SortingNativeHelper(request, self._attr_info)
        elif self._allow_sorting:
            return api_common.SortingEmulatedHelper(request, self._attr_info)
        return api_common.NoSortingHelper(request, self._attr_info)

    def _items(self, request, do_authz=False, parent_id=None):
        """Retrieves and formats a list of elements of the requested entity."""
        # NOTE(salvatore-orlando): The following ensures that fields which
        # are needed for authZ policy validation are not stripped away by the
        # plugin before returning.
        original_fields, fields_to_add = self._do_field_list(
            api_common.list_args(request, 'fields'))
        filters = api_common.get_filters(
            request, self._attr_info,
            ['fields', 'sort_key', 'sort_dir',
             'limit', 'marker', 'page_reverse'],
            is_filter_validation_supported=self._filter_validation)
        kwargs = {'filters': filters,
                  'fields': original_fields}
        sorting_helper = self._get_sorting_helper(request)
        pagination_helper = self._get_pagination_helper(request)
        sorting_helper.update_args(kwargs)
        sorting_helper.update_fields(original_fields, fields_to_add)
        pagination_helper.update_args(kwargs)
        pagination_helper.update_fields(original_fields, fields_to_add)
        if parent_id:
            kwargs[self._parent_id_name] = parent_id
        obj_getter = getattr(self._plugin, self._plugin_handlers[self.LIST])
        obj_list = obj_getter(request.context, **kwargs)
        obj_list = sorting_helper.sort(obj_list)
        obj_list = pagination_helper.paginate(obj_list)
        # Check authz
        if do_authz:
            # FIXME(salvatore-orlando): obj_getter might return references to
            # other resources. Must check authZ on them too.
            # Omit items from list that should not be visible
            tmp_list = []
            for obj in obj_list:
                self._set_parent_id_into_ext_resources_request(
                    request, obj, parent_id, is_get=True)
                if policy.check(
                        request.context, self._plugin_handlers[self.SHOW],
                        obj, plugin=self._plugin, pluralized=self._collection):
                    tmp_list.append(obj)
            obj_list = tmp_list
        # Use the first element in the list for discriminating which attributes
        # should be filtered out because of authZ policies
        # fields_to_add contains a list of attributes added for request policy
        # checks but that were not required by the user. They should be
        # therefore stripped
        fields_to_strip = fields_to_add or []
        if obj_list:
            fields_to_strip += self._exclude_attributes_by_policy(
                request.context, obj_list[0])
        collection = {self._collection:
                      [self._filter_attributes(
                           obj, fields_to_strip=fields_to_strip)
                       for obj in obj_list]}
        pagination_links = pagination_helper.get_links(obj_list)
        if pagination_links:
            collection[self._collection + "_links"] = pagination_links
        # Synchronize usage trackers, if needed
        resource_registry.resync_resource(
            request.context, self._resource, request.context.tenant_id)
        return collection

    def _item(self, request, id, do_authz=False, field_list=None,
              parent_id=None):
        """Retrieves and formats a single element of the requested entity."""
        kwargs = {'fields': field_list}
        action = self._plugin_handlers[self.SHOW]
        if parent_id:
            kwargs[self._parent_id_name] = parent_id
        obj_getter = getattr(self._plugin, action)
        obj = obj_getter(request.context, id, **kwargs)
        self._set_parent_id_into_ext_resources_request(
            request, obj, parent_id, is_get=True)
        # Check authz
        # FIXME(salvatore-orlando): obj_getter might return references to
        # other resources. Must check authZ on them too.
        if do_authz:
            policy.enforce(request.context,
                           action,
                           obj,
                           pluralized=self._collection)
        return obj

    @db_api.retry_db_errors
    def index(self, request, **kwargs):
        """Returns a list of the requested entity."""
        parent_id = kwargs.get(self._parent_id_name)
        # Ensure policy engine is initialized
        policy.init()
        return self._items(request, True, parent_id)

    @db_api.retry_db_errors
    def show(self, request, id, **kwargs):
        """Returns detailed information about the requested entity."""
        try:
            # NOTE(salvatore-orlando): The following ensures that fields
            # which are needed for authZ policy validation are not stripped
            # away by the plugin before returning.
            field_list, added_fields = self._do_field_list(
                api_common.list_args(request, "fields"))
            parent_id = kwargs.get(self._parent_id_name)
            # Ensure policy engine is initialized
            policy.init()
            return {self._resource:
                    self._view(request.context,
                               self._item(request,
                                          id,
                                          do_authz=True,
                                          field_list=field_list,
                                          parent_id=parent_id),
                               fields_to_strip=added_fields)}
        except oslo_policy.PolicyNotAuthorized:
            # To avoid giving away information, pretend that it
            # doesn't exist
            msg = _('The resource could not be found.')
            raise webob.exc.HTTPNotFound(msg)

    def _emulate_bulk_create(self, obj_creator, request, body, parent_id=None):
        objs = []
        try:
            for item in body[self._collection]:
                kwargs = {self._resource: item}
                if parent_id:
                    kwargs[self._parent_id_name] = parent_id
                fields_to_strip = self._exclude_attributes_by_policy(
                    request.context, item)
                objs.append(self._filter_attributes(
                    obj_creator(request.context, **kwargs),
                    fields_to_strip=fields_to_strip))
            return objs
        # Note(salvatore-orlando): broad catch as in theory a plugin
        # could raise any kind of exception
        except Exception:
            with excutils.save_and_reraise_exception():
                for obj in objs:
                    obj_deleter = getattr(self._plugin,
                                          self._plugin_handlers[self.DELETE])
                    try:
                        kwargs = ({self._parent_id_name: parent_id}
                                  if parent_id else {})
                        obj_deleter(request.context, obj['id'], **kwargs)
                    except Exception:
                        # broad catch as our only purpose is to log the
                        # exception
                        LOG.exception("Unable to undo add for "
                                      "%(resource)s %(id)s",
                                      {'resource': self._resource,
                                       'id': obj['id']})
                # TODO(salvatore-orlando): The object being processed when the
                # plugin raised might have been created or not in the db.
                # We need a way for ensuring that if it has been created,
                # it is then deleted

    def create(self, request, body=None, **kwargs):
        self._notifier.info(request.context,
                            self._resource + '.create.start',
                            body)
        return self._create(request, body, **kwargs)

    @db_api.retry_db_errors
    def _create(self, request, body, **kwargs):
        """Creates a new instance of the requested entity."""
        parent_id = kwargs.get(self._parent_id_name)
        body = Controller.prepare_request_body(request.context,
                                               body, True,
                                               self._resource, self._attr_info,
                                               allow_bulk=self._allow_bulk)
        action = self._plugin_handlers[self.CREATE]
        # Check authz
        if self._collection in body:
            # Have to account for bulk create
            items = body[self._collection]
        else:
            items = [body]
        # Ensure policy engine is initialized
        policy.init()
        # Store requested resource amounts grouping them by tenant
        # This won't work with multiple resources. However because of the
        # current structure of this controller there will hardly be more than
        # one resource for which reservations are being made
        request_deltas = collections.defaultdict(int)
        for item in items:
            self._validate_network_tenant_ownership(request,
                                                    item[self._resource])
            # For ext resources policy check, we support two types, such as
            # parent_id is in request body, another type is parent_id is in
            # request url, which we can get from kwargs.
            self._set_parent_id_into_ext_resources_request(
                request, item[self._resource], parent_id)
            policy.enforce(request.context,
                           action,
                           item[self._resource],
                           pluralized=self._collection)
            if 'tenant_id' not in item[self._resource]:
                # no tenant_id - no quota check
                continue
            tenant_id = item[self._resource]['tenant_id']
            request_deltas[tenant_id] += 1
        # Quota enforcement
        reservations = []
        try:
            for (tenant, delta) in request_deltas.items():
                reservation = quota.QUOTAS.make_reservation(
                    request.context,
                    tenant,
                    {self._resource: delta},
                    self._plugin)
                reservations.append(reservation)
        except exceptions.QuotaResourceUnknown as e:
            # We don't want to quota this resource
            LOG.debug(e)

        def notify(create_result):
            # Ensure usage trackers for all resources affected by this API
            # operation are marked as dirty
            with db_api.CONTEXT_WRITER.using(request.context):
                # Commit the reservation(s)
                for reservation in reservations:
                    quota.QUOTAS.commit_reservation(
                        request.context, reservation.reservation_id)
                resource_registry.set_resources_dirty(request.context)

            notifier_method = self._resource + '.create.end'
            self._notifier.info(request.context,
                                notifier_method,
                                create_result)
            registry.publish(self._resource, events.BEFORE_RESPONSE, self,
                             payload=events.APIEventPayload(
                                 request.context, notifier_method, action,
                                 request_body=body,
                                 states=({}, create_result,),
                                 collection_name=self._collection))
            return create_result

        def do_create(body, bulk=False, emulated=False):
            kwargs = {self._parent_id_name: parent_id} if parent_id else {}
            if bulk and not emulated:
                obj_creator = getattr(self._plugin, "%s_bulk" % action)
            else:
                obj_creator = getattr(self._plugin, action)
            try:
                if emulated:
                    return self._emulate_bulk_create(obj_creator, request,
                                                     body, parent_id)
                else:
                    if self._collection in body:
                        # This is weird but fixing it requires changes to the
                        # plugin interface
                        kwargs.update({self._collection: body})
                    else:
                        kwargs.update({self._resource: body})
                    return obj_creator(request.context, **kwargs)
            except Exception:
                # In case of failure the plugin will always raise an
                # exception. Cancel the reservation
                with excutils.save_and_reraise_exception():
                    for reservation in reservations:
                        quota.QUOTAS.cancel_reservation(
                            request.context, reservation.reservation_id)

        if self._collection in body and self._native_bulk:
            # plugin does atomic bulk create operations
            objs = do_create(body, bulk=True)
            # Use first element of list to discriminate attributes which
            # should be removed because of authZ policies
            fields_to_strip = self._exclude_attributes_by_policy(
                request.context, objs[0])
            return notify({self._collection: [self._filter_attributes(
                obj, fields_to_strip=fields_to_strip)
                for obj in objs]})
        else:
            if self._collection in body:
                # Emulate atomic bulk behavior
                objs = do_create(body, bulk=True, emulated=True)
                return notify({self._collection: objs})
            else:
                obj = do_create(body)
                return notify({self._resource: self._view(request.context,
                                                          obj)})

    def delete(self, request, id, **kwargs):
        """Deletes the specified entity."""
        if request.body:
            msg = _('Request body is not supported in DELETE.')
            raise webob.exc.HTTPBadRequest(msg)
        self._notifier.info(request.context,
                            self._resource + '.delete.start',
                            {self._resource + '_id': id})
        return self._delete(request, id, **kwargs)

    @db_api.retry_db_errors
    def _delete(self, request, id, **kwargs):
        action = self._plugin_handlers[self.DELETE]

        # Check authz
        policy.init()
        parent_id = kwargs.get(self._parent_id_name)
        obj = self._item(request, id, parent_id=parent_id)
        try:
            policy.enforce(request.context,
                           action,
                           obj,
                           pluralized=self._collection)
        except oslo_policy.PolicyNotAuthorized:
            # To avoid giving away information, pretend that it
            # doesn't exist if policy does not authorize SHOW
            with excutils.save_and_reraise_exception() as ctxt:
                if not policy.check(request.context,
                                    self._plugin_handlers[self.SHOW],
                                    obj,
                                    pluralized=self._collection):
                    ctxt.reraise = False
            msg = _('The resource could not be found.')
            raise webob.exc.HTTPNotFound(msg)

        obj_deleter = getattr(self._plugin, action)
        obj_deleter(request.context, id, **kwargs)
        # A delete operation usually alters resource usage, so mark affected
        # usage trackers as dirty
        resource_registry.set_resources_dirty(request.context)
        notifier_method = self._resource + '.delete.end'
        result = {self._resource: self._view(request.context, obj)}
        notifier_payload = {self._resource + '_id': id}
        notifier_payload.update(result)
        self._notifier.info(request.context,
                            notifier_method,
                            notifier_payload)

        registry.publish(self._resource, events.BEFORE_RESPONSE, self,
                         payload=events.APIEventPayload(
                             request.context, notifier_method, action,
                             states=({}, obj, result,),
                             collection_name=self._collection))

    def update(self, request, id, body=None, **kwargs):
        """Updates the specified entity's attributes."""
        try:
            payload = body.copy()
        except AttributeError:
            msg = _("Invalid format: %s") % request.body
            raise exceptions.BadRequest(resource='body', msg=msg)
        payload['id'] = id
        self._notifier.info(request.context,
                            self._resource + '.update.start',
                            payload)
        return self._update(request, id, body, **kwargs)

    @db_api.retry_db_errors
    def _update(self, request, id, body, **kwargs):
        body = Controller.prepare_request_body(request.context,
                                               body, False,
                                               self._resource, self._attr_info,
                                               allow_bulk=self._allow_bulk)
        action = self._plugin_handlers[self.UPDATE]
        # Load object to check authz
        # but pass only attributes in the original body and required
        # by the policy engine to the policy 'brain'
        field_list = [name for (name, value) in self._attr_info.items()
                      if (value.get('required_by_policy') or
                          value.get('primary_key') or
                          'default' not in value)]
        # Ensure policy engine is initialized
        policy.init()
        parent_id = kwargs.get(self._parent_id_name)
        # If the parent_id exist, we should get orig_obj with
        # self._parent_id_name field.
        if parent_id and self._parent_id_name not in field_list:
            field_list.append(self._parent_id_name)
        orig_obj = self._item(request, id, field_list=field_list,
                              parent_id=parent_id)
        orig_object_copy = copy.copy(orig_obj)
        orig_obj.update(body[self._resource])
        # Make a list of attributes to be updated to inform the policy engine
        # which attributes are set explicitly so that it can distinguish them
        # from the ones that are set to their default values.
        orig_obj[n_const.ATTRIBUTES_TO_UPDATE] = body[self._resource].keys()
        # Then get the ext_parent_id, format to ext_parent_parent_resource_id
        if self._parent_id_name in orig_obj:
            self._set_parent_id_into_ext_resources_request(
                request, orig_obj, parent_id)
        try:
            policy.enforce(request.context,
                           action,
                           orig_obj,
                           pluralized=self._collection)
        except oslo_policy.PolicyNotAuthorized:
            # To avoid giving away information, pretend that it
            # doesn't exist if policy does not authorize SHOW
            with excutils.save_and_reraise_exception() as ctxt:
                if not policy.check(request.context,
                                    self._plugin_handlers[self.SHOW],
                                    orig_obj,
                                    pluralized=self._collection):
                    ctxt.reraise = False
            msg = _('The resource could not be found.')
            raise webob.exc.HTTPNotFound(msg)

        obj_updater = getattr(self._plugin, action)
        kwargs = {self._resource: body}
        if parent_id:
            kwargs[self._parent_id_name] = parent_id
        obj = obj_updater(request.context, id, **kwargs)
        # Usually an update operation does not alter resource usage, but as
        # there might be side effects it might be worth checking for changes
        # in resource usage here as well (e.g: a tenant port is created when a
        # router interface is added)
        resource_registry.set_resources_dirty(request.context)

        result = {self._resource: self._view(request.context, obj)}
        notifier_method = self._resource + '.update.end'
        self._notifier.info(request.context, notifier_method, result)
        registry.publish(self._resource, events.BEFORE_RESPONSE, self,
                         payload=events.APIEventPayload(
                             request.context, notifier_method, action,
                             request_body=body,
                             states=(orig_object_copy, result,),
                             collection_name=self._collection))
        return result

    @staticmethod
    def prepare_request_body(context, body, is_create, resource, attr_info,
                             allow_bulk=False):
        """Verifies required attributes are in request body.

        Also checking that an attribute is only specified if it is allowed
        for the given operation (create/update).

        Attribute with default values are considered to be optional.

        body argument must be the deserialized body.
        """
        collection = resource + "s"
        if not body:
            raise webob.exc.HTTPBadRequest(_("Resource body required"))

        LOG.debug("Request body: %(body)s", {'body': body})
        try:
            if collection in body:
                if not allow_bulk:
                    raise webob.exc.HTTPBadRequest(_("Bulk operation "
                                                     "not supported"))
                if not body[collection]:
                    raise webob.exc.HTTPBadRequest(_("Resources required"))
                bulk_body = [
                    Controller.prepare_request_body(
                        context, item if resource in item
                        else {resource: item}, is_create, resource, attr_info,
                        allow_bulk) for item in body[collection]
                ]
                return {collection: bulk_body}
            res_dict = body.get(resource)
        except (AttributeError, TypeError):
            msg = _("Body contains invalid data")
            raise webob.exc.HTTPBadRequest(msg)
        if res_dict is None:
            msg = _("Unable to find '%s' in request body") % resource
            raise webob.exc.HTTPBadRequest(msg)
        if not isinstance(res_dict, dict):
            msg = _("Object '%s' contains invalid data") % resource
            raise webob.exc.HTTPBadRequest(msg)

        attr_ops = attributes.AttributeInfo(attr_info)
        attr_ops.populate_project_id(context, res_dict, is_create)
        attributes.populate_project_info(attr_info)
        attr_ops.verify_attributes(res_dict)

        if is_create:  # POST
            attr_ops.fill_post_defaults(
                res_dict, exc_cls=webob.exc.HTTPBadRequest)
        else:  # PUT
            for attr, attr_vals in attr_info.items():
                if attr in res_dict and not attr_vals['allow_put']:
                    msg = _("Cannot update read-only attribute %s") % attr
                    raise webob.exc.HTTPBadRequest(msg)

        attr_ops.convert_values(res_dict, exc_cls=webob.exc.HTTPBadRequest)
        return body

    def _validate_network_tenant_ownership(self, request, resource_item):
        # TODO(salvatore-orlando): consider whether this check can be folded
        # in the policy engine
        if (request.context.is_admin or request.context.is_advsvc or
                self._resource not in ('port', 'subnet')):
            return
        network = self._plugin.get_network(
            request.context,
            resource_item['network_id'])
        # do not perform the check on shared networks
        if network.get('shared'):
            return

        network_owner = network['tenant_id']

        if network_owner != resource_item['tenant_id']:
            # NOTE(kevinbenton): we raise a 404 to hide the existence of the
            # network from the tenant since they don't have access to it.
            msg = _('The resource could not be found.')
            raise webob.exc.HTTPNotFound(msg)

    def _set_parent_id_into_ext_resources_request(
            self, request, resource_item, parent_id, is_get=False):
        if not parent_id:
            return

        # This will pass most create/update/delete cases
        if not is_get and (request.context.is_admin or
                           request.context.is_advsvc or
                           self.parent['member_name'] not in
                           n_const.EXT_PARENT_RESOURCE_MAPPING or
                           resource_item.get(self._parent_id_name)):
            return

        # Then we arrive here, that means the request or get obj contains
        # ext_parent. If this func is called by list/get, and it contains
        # _parent_id_name. We need to re-add the ex_parent prefix to policy.
        if is_get:
            if (not request.context.is_admin or
                    not request.context.is_advsvc and
                    self.parent['member_name'] in
                    n_const.EXT_PARENT_RESOURCE_MAPPING):
                resource_item.setdefault(
                    "%s_%s" % (n_const.EXT_PARENT_PREFIX,
                               self._parent_id_name),
                    parent_id)
        # If this func is called by create/update/delete, we just add.
        else:
            resource_item.setdefault(
                "%s_%s" % (n_const.EXT_PARENT_PREFIX, self._parent_id_name),
                parent_id)


def create_resource(collection, resource, plugin, params, allow_bulk=False,
                    member_actions=None, parent=None, allow_pagination=False,
                    allow_sorting=False):
    controller = Controller(plugin, collection, resource, params, allow_bulk,
                            member_actions=member_actions, parent=parent,
                            allow_pagination=allow_pagination,
                            allow_sorting=allow_sorting)

    return wsgi_resource.Resource(controller, faults.FAULT_MAP)
