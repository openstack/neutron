# Copyright (c) 2015 Taturiello Consulting, Meh.
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
import functools

from neutron_lib import constants
from oslo_config import cfg
import pecan
from pecan import request
import six

from neutron.api import api_common
from neutron.api.v2 import attributes as api_attributes
from neutron.db import api as db_api
from neutron import manager

# Utility functions for Pecan controllers.


class Fakecode(object):
    co_varnames = ()


def _composed(*decorators):
    """Takes a list of decorators and returns a single decorator."""

    def final_decorator(f):
        for d in decorators:
            # workaround for pecan bug that always assumes decorators
            # have a __code__ attr
            if not hasattr(d, '__code__'):
                setattr(d, '__code__', Fakecode())
            f = d(f)
        return f
    return final_decorator


def _protect_original_resources(f):
    """Wrapper to ensure that mutated resources are discarded on retries."""

    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        ctx = request.context
        if 'resources' in ctx:
            orig = ctx.get('protected_resources')
            if not orig:
                # this is the first call so we just take the whole reference
                ctx['protected_resources'] = ctx['resources']
            # TODO(blogan): Once bug 157751 is fixed and released in
            # neutron-lib this memo will no longer be needed.  This is just
            # quick way to not depend on a release of neutron-lib.
            # The version that has that bug fix will need to be updated in
            # neutron-lib.
            memo = {id(constants.ATTR_NOT_SPECIFIED):
                    constants.ATTR_NOT_SPECIFIED}
            ctx['resources'] = copy.deepcopy(ctx['protected_resources'],
                                             memo=memo)
        return f(*args, **kwargs)
    return wrapped


def _pecan_generator_wrapper(func, *args, **kwargs):
    """Helper function so we don't have to specify json for everything."""
    kwargs.setdefault('content_type', 'application/json')
    kwargs.setdefault('template', 'json')
    return _composed(_protect_original_resources, db_api.retry_db_errors,
                     func(*args, **kwargs))


def expose(*args, **kwargs):
    return _pecan_generator_wrapper(pecan.expose, *args, **kwargs)


def when(index, *args, **kwargs):
    return _pecan_generator_wrapper(index.when, *args, **kwargs)


class NeutronPecanController(object):

    LIST = 'list'
    SHOW = 'show'
    CREATE = 'create'
    UPDATE = 'update'
    DELETE = 'delete'

    def __init__(self, collection, resource, plugin=None, resource_info=None,
                 allow_pagination=None, allow_sorting=None,
                 parent_resource=None, member_actions=None):
        # Ensure dashes are always replaced with underscores
        self.collection = collection and collection.replace('-', '_')
        self.resource = resource and resource.replace('-', '_')
        self._member_actions = member_actions or {}
        self._resource_info = resource_info
        self._plugin = plugin
        # Controllers for some resources that are not mapped to anything in
        # RESOURCE_ATTRIBUTE_MAP will not have anything in _resource_info
        if self.resource_info:
            self._mandatory_fields = set([field for (field, data) in
                                          self.resource_info.items() if
                                          data.get('required_by_policy')])
        else:
            self._mandatory_fields = set()
        self.allow_pagination = allow_pagination
        if self.allow_pagination is None:
            self.allow_pagination = cfg.CONF.allow_pagination
        self.allow_sorting = allow_sorting
        if self.allow_sorting is None:
            self.allow_sorting = cfg.CONF.allow_sorting
        self.native_pagination = api_common.is_native_pagination_supported(
            self.plugin)
        self.native_sorting = api_common.is_native_sorting_supported(
            self.plugin)
        self.primary_key = self._get_primary_key()

        self.parent = parent_resource
        parent_resource = '_%s' % parent_resource if parent_resource else ''
        self._parent_id_name = ('%s_id' % parent_resource
                                if parent_resource else None)
        self._plugin_handlers = {
            self.LIST: 'get%s_%s' % (parent_resource, self.collection),
            self.SHOW: 'get%s_%s' % (parent_resource, self.resource)
        }
        for action in [self.CREATE, self.UPDATE, self.DELETE]:
            self._plugin_handlers[action] = '%s%s_%s' % (
                action, parent_resource, self.resource)

    def build_field_list(self, request_fields):
        added_fields = []
        combined_fields = []
        if request_fields:
            req_fields_set = set(request_fields)
            added_fields = self._mandatory_fields - req_fields_set
            combined_fields = req_fields_set | self._mandatory_fields
        return list(combined_fields), list(added_fields)

    @property
    def plugin(self):
        if not self._plugin:
            self._plugin = manager.NeutronManager.get_plugin_for_resource(
                self.resource)
        return self._plugin

    @property
    def resource_info(self):
        if not self._resource_info:
            self._resource_info = api_attributes.get_collection_info(
                self.collection)
        return self._resource_info

    def _get_primary_key(self, default_primary_key='id'):
        if not self.resource_info:
            return default_primary_key
        for key, value in six.iteritems(self.resource_info):
            if value.get('primary_key', False):
                return key
        return default_primary_key

    @property
    def plugin_handlers(self):
        return self._plugin_handlers

    @property
    def plugin_lister(self):
        return getattr(self.plugin, self._plugin_handlers[self.LIST])

    @property
    def plugin_shower(self):
        return getattr(self.plugin, self._plugin_handlers[self.SHOW])

    @property
    def plugin_creator(self):
        return getattr(self.plugin, self._plugin_handlers[self.CREATE])

    @property
    def plugin_bulk_creator(self):
        return getattr(self.plugin,
                       '%s_bulk' % self._plugin_handlers[self.CREATE])

    @property
    def plugin_deleter(self):
        return getattr(self.plugin, self._plugin_handlers[self.DELETE])

    @property
    def plugin_updater(self):
        return getattr(self.plugin, self._plugin_handlers[self.UPDATE])


class ShimRequest(object):

    def __init__(self, context):
        self.context = context


class ShimItemController(NeutronPecanController):

    def __init__(self, collection, resource, item, controller):
        super(ShimItemController, self).__init__(collection, resource)
        self.item = item
        self.controller_delete = getattr(controller, 'delete', None)

    @expose(generic=True)
    def index(self):
        pecan.abort(405)

    @when(index, method='DELETE')
    def delete(self):
        if not self.controller_delete:
            pecan.abort(405)
        pecan.response.status = 204
        shim_request = ShimRequest(request.context['neutron_context'])
        uri_identifiers = request.context['uri_identifiers']
        return self.controller_delete(shim_request, self.item,
                                      **uri_identifiers)


class ShimCollectionsController(NeutronPecanController):

    def __init__(self, collection, resource, controller):
        super(ShimCollectionsController, self).__init__(collection, resource)
        self.controller = controller
        self.controller_index = getattr(controller, 'index', None)
        self.controller_create = getattr(controller, 'create', None)

    @expose(generic=True)
    def index(self):
        if not self.controller_index:
            pecan.abort(405)
        shim_request = ShimRequest(request.context['neutron_context'])
        uri_identifiers = request.context['uri_identifiers']
        return self.controller_index(shim_request, **uri_identifiers)

    @when(index, method='POST')
    def create(self):
        if not self.controller_create:
            pecan.abort(405)
        pecan.response.status = 201
        shim_request = ShimRequest(request.context['neutron_context'])
        uri_identifiers = request.context['uri_identifiers']
        return self.controller_create(shim_request, request.json,
                                      **uri_identifiers)

    @expose()
    def _lookup(self, item, *remainder):
        request.context['resource'] = self.resource
        request.context['resource_id'] = item
        return ShimItemController(self.collection, self.resource, item,
                                  self.controller), remainder


class PecanResourceExtension(object):

    def __init__(self, collection, controller, plugin):
        self.collection = collection
        self.controller = controller
        self.plugin = plugin
