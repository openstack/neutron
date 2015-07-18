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

import copy

import netaddr
from oslo_config import cfg
from oslo_log import log as logging
from oslo_policy import policy as oslo_policy
from oslo_utils import excutils
import six
import webob.exc

from neutron.api import api_common
from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.api.v2 import attributes
from neutron.api.v2 import resource as wsgi_resource
from neutron.common import constants as const
from neutron.common import exceptions
from neutron.common import rpc as n_rpc
from neutron.db import api as db_api
from neutron.i18n import _LE, _LI
from neutron import policy
from neutron import quota


LOG = logging.getLogger(__name__)

FAULT_MAP = {exceptions.NotFound: webob.exc.HTTPNotFound,
             exceptions.Conflict: webob.exc.HTTPConflict,
             exceptions.InUse: webob.exc.HTTPConflict,
             exceptions.BadRequest: webob.exc.HTTPBadRequest,
             exceptions.ServiceUnavailable: webob.exc.HTTPServiceUnavailable,
             exceptions.NotAuthorized: webob.exc.HTTPForbidden,
             netaddr.AddrFormatError: webob.exc.HTTPBadRequest,
             oslo_policy.PolicyNotAuthorized: webob.exc.HTTPForbidden
             }


class Controller(object):
    LIST = 'list'
    SHOW = 'show'
    CREATE = 'create'
    UPDATE = 'update'
    DELETE = 'delete'

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
        self._policy_attrs = [name for (name, info) in self._attr_info.items()
                              if info.get('required_by_policy')]
        self._notifier = n_rpc.get_notifier('network')
        # use plugin's dhcp notifier, if this is already instantiated
        agent_notifiers = getattr(plugin, 'agent_notifiers', {})
        self._dhcp_agent_notifier = (
            agent_notifiers.get(const.AGENT_TYPE_DHCP) or
            dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        )
        if cfg.CONF.notify_nova_on_port_data_changes:
            from neutron.notifiers import nova
            self._nova_notifier = nova.Notifier()
        self._member_actions = member_actions
        self._primary_key = self._get_primary_key()
        if self._allow_pagination and self._native_pagination:
            # Native pagination need native sorting support
            if not self._native_sorting:
                raise exceptions.Invalid(
                    _("Native pagination depend on native sorting")
                )
            if not self._allow_sorting:
                LOG.info(_LI("Allow sorting is enabled because native "
                             "pagination requires native sorting"))
                self._allow_sorting = True

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
        for key, value in six.iteritems(self._attr_info):
            if value.get('primary_key', False):
                return key
        return default_primary_key

    def _is_native_bulk_supported(self):
        native_bulk_attr_name = ("_%s__native_bulk_support"
                                 % self._plugin.__class__.__name__)
        return getattr(self._plugin, native_bulk_attr_name, False)

    def _is_native_pagination_supported(self):
        native_pagination_attr_name = ("_%s__native_pagination_support"
                                       % self._plugin.__class__.__name__)
        return getattr(self._plugin, native_pagination_attr_name, False)

    def _is_native_sorting_supported(self):
        native_sorting_attr_name = ("_%s__native_sorting_support"
                                    % self._plugin.__class__.__name__)
        return getattr(self._plugin, native_sorting_attr_name, False)

    def _exclude_attributes_by_policy(self, context, data):
        """Identifies attributes to exclude according to authZ policies.

        Return a list of attribute names which should be stripped from the
        response returned to the user because the user is not authorized
        to see them.
        """
        attributes_to_exclude = []
        for attr_name in data.keys():
            attr_data = self._attr_info.get(attr_name)
            if attr_data and attr_data['is_visible']:
                if policy.check(
                    context,
                    '%s:%s' % (self._plugin_handlers[self.SHOW], attr_name),
                    data,
                    might_not_exist=True,
                    pluralized=self._collection):
                    # this attribute is visible, check next one
                    continue
            # if the code reaches this point then either the policy check
            # failed or the attribute was not visible in the first place
            attributes_to_exclude.append(attr_name)
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
        return self._filter_attributes(context, data, fields_to_strip)

    def _filter_attributes(self, context, data, fields_to_strip=None):
        if not fields_to_strip:
            return data
        return dict(item for item in six.iteritems(data)
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
                    resource = self._item(request, id, True)
                except oslo_policy.PolicyNotAuthorized:
                    msg = _('The resource could not be found.')
                    raise webob.exc.HTTPNotFound(msg)
                body = copy.deepcopy(kwargs.pop('body', None))
                # Explicit comparison with None to distinguish from {}
                if body is not None:
                    arg_list.append(body)
                # It is ok to raise a 403 because accessibility to the
                # object was checked earlier in this method
                policy.enforce(request.context,
                               name,
                               resource,
                               pluralized=self._collection)
                return getattr(self._plugin, name)(*arg_list, **kwargs)
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
        filters = api_common.get_filters(request, self._attr_info,
                                         ['fields', 'sort_key', 'sort_dir',
                                          'limit', 'marker', 'page_reverse'])
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
            obj_list = [obj for obj in obj_list
                        if policy.check(request.context,
                                        self._plugin_handlers[self.SHOW],
                                        obj,
                                        plugin=self._plugin,
                                        pluralized=self._collection)]
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
                          request.context, obj,
                          fields_to_strip=fields_to_strip)
                       for obj in obj_list]}
        pagination_links = pagination_helper.get_links(obj_list)
        if pagination_links:
            collection[self._collection + "_links"] = pagination_links
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
        # Check authz
        # FIXME(salvatore-orlando): obj_getter might return references to
        # other resources. Must check authZ on them too.
        if do_authz:
            policy.enforce(request.context,
                           action,
                           obj,
                           pluralized=self._collection)
        return obj

    def _send_dhcp_notification(self, context, data, methodname):
        if cfg.CONF.dhcp_agent_notification:
            if self._collection in data:
                for body in data[self._collection]:
                    item = {self._resource: body}
                    self._dhcp_agent_notifier.notify(context, item, methodname)
            else:
                self._dhcp_agent_notifier.notify(context, data, methodname)

    def _send_nova_notification(self, action, orig, returned):
        if hasattr(self, '_nova_notifier'):
            self._nova_notifier.send_network_change(action, orig, returned)

    def index(self, request, **kwargs):
        """Returns a list of the requested entity."""
        parent_id = kwargs.get(self._parent_id_name)
        # Ensure policy engine is initialized
        policy.init()
        return self._items(request, True, parent_id)

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
                    request.context,
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
                        LOG.exception(_LE("Unable to undo add for "
                                          "%(resource)s %(id)s"),
                                      {'resource': self._resource,
                                       'id': obj['id']})
                # TODO(salvatore-orlando): The object being processed when the
                # plugin raised might have been created or not in the db.
                # We need a way for ensuring that if it has been created,
                # it is then deleted

    @db_api.retry_db_errors
    def create(self, request, body=None, **kwargs):
        """Creates a new instance of the requested entity."""
        parent_id = kwargs.get(self._parent_id_name)
        self._notifier.info(request.context,
                            self._resource + '.create.start',
                            body)
        body = Controller.prepare_request_body(request.context,
                                               copy.deepcopy(body), True,
                                               self._resource, self._attr_info,
                                               allow_bulk=self._allow_bulk)
        action = self._plugin_handlers[self.CREATE]
        # Check authz
        if self._collection in body:
            # Have to account for bulk create
            items = body[self._collection]
            deltas = {}
            bulk = True
        else:
            items = [body]
            bulk = False
        # Ensure policy engine is initialized
        policy.init()
        for item in items:
            self._validate_network_tenant_ownership(request,
                                                    item[self._resource])
            policy.enforce(request.context,
                           action,
                           item[self._resource],
                           pluralized=self._collection)
            if 'tenant_id' not in item[self._resource]:
                # no tenant_id - no quota check
                continue
            try:
                tenant_id = item[self._resource]['tenant_id']
                count = quota.QUOTAS.count(request.context, self._resource,
                                           self._plugin, self._collection,
                                           tenant_id)
                if bulk:
                    delta = deltas.get(tenant_id, 0) + 1
                    deltas[tenant_id] = delta
                else:
                    delta = 1
                kwargs = {self._resource: count + delta}
            except exceptions.QuotaResourceUnknown as e:
                # We don't want to quota this resource
                LOG.debug(e)
            else:
                quota.QUOTAS.limit_check(request.context,
                                         item[self._resource]['tenant_id'],
                                         **kwargs)

        def notify(create_result):
            notifier_method = self._resource + '.create.end'
            self._notifier.info(request.context,
                                notifier_method,
                                create_result)
            self._send_dhcp_notification(request.context,
                                         create_result,
                                         notifier_method)
            return create_result

        kwargs = {self._parent_id_name: parent_id} if parent_id else {}
        if self._collection in body and self._native_bulk:
            # plugin does atomic bulk create operations
            obj_creator = getattr(self._plugin, "%s_bulk" % action)
            objs = obj_creator(request.context, body, **kwargs)
            # Use first element of list to discriminate attributes which
            # should be removed because of authZ policies
            fields_to_strip = self._exclude_attributes_by_policy(
                request.context, objs[0])
            return notify({self._collection: [self._filter_attributes(
                request.context, obj, fields_to_strip=fields_to_strip)
                for obj in objs]})
        else:
            obj_creator = getattr(self._plugin, action)
            if self._collection in body:
                # Emulate atomic bulk behavior
                objs = self._emulate_bulk_create(obj_creator, request,
                                                 body, parent_id)
                return notify({self._collection: objs})
            else:
                kwargs.update({self._resource: body})
                obj = obj_creator(request.context, **kwargs)
                self._send_nova_notification(action, {},
                                             {self._resource: obj})
                return notify({self._resource: self._view(request.context,
                                                          obj)})

    @db_api.retry_db_errors
    def delete(self, request, id, **kwargs):
        """Deletes the specified entity."""
        self._notifier.info(request.context,
                            self._resource + '.delete.start',
                            {self._resource + '_id': id})
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
            # doesn't exist
            msg = _('The resource could not be found.')
            raise webob.exc.HTTPNotFound(msg)

        obj_deleter = getattr(self._plugin, action)
        obj_deleter(request.context, id, **kwargs)
        notifier_method = self._resource + '.delete.end'
        self._notifier.info(request.context,
                            notifier_method,
                            {self._resource + '_id': id})
        result = {self._resource: self._view(request.context, obj)}
        self._send_nova_notification(action, {}, result)
        self._send_dhcp_notification(request.context,
                                     result,
                                     notifier_method)

    @db_api.retry_db_errors
    def update(self, request, id, body=None, **kwargs):
        """Updates the specified entity's attributes."""
        parent_id = kwargs.get(self._parent_id_name)
        try:
            payload = body.copy()
        except AttributeError:
            msg = _("Invalid format: %s") % request.body
            raise exceptions.BadRequest(resource='body', msg=msg)
        payload['id'] = id
        self._notifier.info(request.context,
                            self._resource + '.update.start',
                            payload)
        body = Controller.prepare_request_body(request.context, body, False,
                                               self._resource, self._attr_info,
                                               allow_bulk=self._allow_bulk)
        action = self._plugin_handlers[self.UPDATE]
        # Load object to check authz
        # but pass only attributes in the original body and required
        # by the policy engine to the policy 'brain'
        field_list = [name for (name, value) in six.iteritems(self._attr_info)
                      if (value.get('required_by_policy') or
                          value.get('primary_key') or
                          'default' not in value)]
        # Ensure policy engine is initialized
        policy.init()
        orig_obj = self._item(request, id, field_list=field_list,
                              parent_id=parent_id)
        orig_object_copy = copy.copy(orig_obj)
        orig_obj.update(body[self._resource])
        # Make a list of attributes to be updated to inform the policy engine
        # which attributes are set explicitly so that it can distinguish them
        # from the ones that are set to their default values.
        orig_obj[const.ATTRIBUTES_TO_UPDATE] = body[self._resource].keys()
        try:
            policy.enforce(request.context,
                           action,
                           orig_obj,
                           pluralized=self._collection)
        except oslo_policy.PolicyNotAuthorized:
            with excutils.save_and_reraise_exception() as ctxt:
                # If a tenant is modifying it's own object, it's safe to return
                # a 403. Otherwise, pretend that it doesn't exist to avoid
                # giving away information.
                if request.context.tenant_id != orig_obj['tenant_id']:
                    ctxt.reraise = False
            msg = _('The resource could not be found.')
            raise webob.exc.HTTPNotFound(msg)

        obj_updater = getattr(self._plugin, action)
        kwargs = {self._resource: body}
        if parent_id:
            kwargs[self._parent_id_name] = parent_id
        obj = obj_updater(request.context, id, **kwargs)
        result = {self._resource: self._view(request.context, obj)}
        notifier_method = self._resource + '.update.end'
        self._notifier.info(request.context, notifier_method, result)
        self._send_dhcp_notification(request.context,
                                     result,
                                     notifier_method)
        self._send_nova_notification(action, orig_object_copy, result)
        return result

    @staticmethod
    def _populate_tenant_id(context, res_dict, attr_info, is_create):
        if (('tenant_id' in res_dict and
             res_dict['tenant_id'] != context.tenant_id and
             not context.is_admin)):
            msg = _("Specifying 'tenant_id' other than authenticated "
                    "tenant in request requires admin privileges")
            raise webob.exc.HTTPBadRequest(msg)

        if is_create and 'tenant_id' not in res_dict:
            if context.tenant_id:
                res_dict['tenant_id'] = context.tenant_id
            elif 'tenant_id' in attr_info:
                msg = _("Running without keystone AuthN requires "
                        "that tenant_id is specified")
                raise webob.exc.HTTPBadRequest(msg)

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

        Controller._populate_tenant_id(context, res_dict, attr_info, is_create)
        Controller._verify_attributes(res_dict, attr_info)

        if is_create:  # POST
            for attr, attr_vals in six.iteritems(attr_info):
                if attr_vals['allow_post']:
                    if ('default' not in attr_vals and
                        attr not in res_dict):
                        msg = _("Failed to parse request. Required "
                                "attribute '%s' not specified") % attr
                        raise webob.exc.HTTPBadRequest(msg)
                    res_dict[attr] = res_dict.get(attr,
                                                  attr_vals.get('default'))
                else:
                    if attr in res_dict:
                        msg = _("Attribute '%s' not allowed in POST") % attr
                        raise webob.exc.HTTPBadRequest(msg)
        else:  # PUT
            for attr, attr_vals in six.iteritems(attr_info):
                if attr in res_dict and not attr_vals['allow_put']:
                    msg = _("Cannot update read-only attribute %s") % attr
                    raise webob.exc.HTTPBadRequest(msg)

        for attr, attr_vals in six.iteritems(attr_info):
            if (attr not in res_dict or
                res_dict[attr] is attributes.ATTR_NOT_SPECIFIED):
                continue
            # Convert values if necessary
            if 'convert_to' in attr_vals:
                res_dict[attr] = attr_vals['convert_to'](res_dict[attr])
            # Check that configured values are correct
            if 'validate' not in attr_vals:
                continue
            for rule in attr_vals['validate']:
                res = attributes.validators[rule](res_dict[attr],
                                                  attr_vals['validate'][rule])
                if res:
                    msg_dict = dict(attr=attr, reason=res)
                    msg = _("Invalid input for %(attr)s. "
                            "Reason: %(reason)s.") % msg_dict
                    raise webob.exc.HTTPBadRequest(msg)
        return body

    @staticmethod
    def _verify_attributes(res_dict, attr_info):
        extra_keys = set(res_dict.keys()) - set(attr_info.keys())
        if extra_keys:
            msg = _("Unrecognized attribute(s) '%s'") % ', '.join(extra_keys)
            raise webob.exc.HTTPBadRequest(msg)

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
            msg = _("Tenant %(tenant_id)s not allowed to "
                    "create %(resource)s on this network")
            raise webob.exc.HTTPForbidden(msg % {
                "tenant_id": resource_item['tenant_id'],
                "resource": self._resource,
            })


def create_resource(collection, resource, plugin, params, allow_bulk=False,
                    member_actions=None, parent=None, allow_pagination=False,
                    allow_sorting=False):
    controller = Controller(plugin, collection, resource, params, allow_bulk,
                            member_actions=member_actions, parent=parent,
                            allow_pagination=allow_pagination,
                            allow_sorting=allow_sorting)

    return wsgi_resource.Resource(controller, FAULT_MAP)
