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

import pecan
from pecan import request

from neutron.api.v2 import attributes as api_attributes
from neutron import manager

# Utility functions for Pecan controllers.


def expose(*args, **kwargs):
    """Helper function so we don't have to specify json for everything."""
    kwargs.setdefault('content_type', 'application/json')
    kwargs.setdefault('template', 'json')
    return pecan.expose(*args, **kwargs)


def when(index, *args, **kwargs):
    """Helper function so we don't have to specify json for everything."""
    kwargs.setdefault('content_type', 'application/json')
    kwargs.setdefault('template', 'json')
    return index.when(*args, **kwargs)


class NeutronPecanController(object):

    def __init__(self, collection, resource):
        # Ensure dashes are always replaced with underscores
        self.collection = collection and collection.replace('-', '_')
        self.resource = resource and resource.replace('-', '_')
        self._resource_info = api_attributes.get_collection_info(collection)
        self._plugin = None

    @property
    def plugin(self):
        if not self._plugin:
            self._plugin = manager.NeutronManager.get_plugin_for_resource(
                self.resource)
        return self._plugin


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
