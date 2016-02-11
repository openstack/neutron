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

from neutron.pecan_wsgi.controllers import utils


class CollectionsController(utils.NeutronPecanController):

    @utils.expose()
    def _lookup(self, item, *remainder):
        # Store resource identifier in request context
        request.context['resource_id'] = item
        return ItemController(self.resource, item), remainder

    @utils.expose(generic=True)
    def index(self, *args, **kwargs):
        return self.get(*args, **kwargs)

    def get(self, *args, **kwargs):
        # list request
        # TODO(kevinbenton): use user-provided fields in call to plugin
        # after making sure policy enforced fields remain
        kwargs.pop('fields', None)
        _listify = lambda x: x if isinstance(x, list) else [x]
        filters = {k: _listify(v) for k, v in kwargs.items()}
        # TODO(kevinbenton): convert these using api_common.get_filters
        lister = getattr(self.plugin, 'get_%s' % self.collection)
        neutron_context = request.context['neutron_context']
        return {self.collection: lister(neutron_context, filters=filters)}

    @utils.when(index, method='HEAD')
    @utils.when(index, method='PATCH')
    @utils.when(index, method='PUT')
    @utils.when(index, method='DELETE')
    def not_supported(self):
        pecan.abort(405)

    @utils.when(index, method='POST')
    def post(self, *args, **kwargs):
        # TODO(kevinbenton): emulated bulk!
        resources = request.context['resources']
        pecan.response.status = 201
        return self.create(resources)

    def create(self, resources):
        if len(resources) > 1:
            # Bulk!
            method = 'create_%s_bulk' % self.resource
            key = self.collection
            data = {key: [{self.resource: res} for res in resources]}
        else:
            method = 'create_%s' % self.resource
            key = self.resource
            data = {key: resources[0]}
        creator = getattr(self.plugin, method)
        neutron_context = request.context['neutron_context']
        return {key: creator(neutron_context, data)}


class ItemController(utils.NeutronPecanController):

    def __init__(self, resource, item):
        super(ItemController, self).__init__(None, resource)
        self.item = item

    @utils.expose(generic=True)
    def index(self, *args, **kwargs):
        return self.get()

    def get(self, *args, **kwargs):
        getter = getattr(self.plugin, 'get_%s' % self.resource)
        neutron_context = request.context['neutron_context']
        return {self.resource: getter(neutron_context, self.item)}

    @utils.when(index, method='HEAD')
    @utils.when(index, method='POST')
    @utils.when(index, method='PATCH')
    def not_supported(self):
        pecan.abort(405)

    @utils.when(index, method='PUT')
    def put(self, *args, **kwargs):
        neutron_context = request.context['neutron_context']
        if request.member_action:
            member_action_method = getattr(self.plugin,
                                           request.member_action)
            return member_action_method(neutron_context, self.item,
                                        request.prepared_data)
        # TODO(kevinbenton): bulk?
        updater = getattr(self.plugin, 'update_%s' % self.resource)
        resources = request.context['resources']
        # Bulk update is not supported, 'resources' always contains a single
        # elemenet
        data = {self.resource: resources[0]}
        return updater(neutron_context, self.item, data)

    @utils.when(index, method='DELETE')
    def delete(self):
        # TODO(kevinbenton): setting code could be in a decorator
        pecan.response.status = 204
        neutron_context = request.context['neutron_context']
        deleter = getattr(self.plugin, 'delete_%s' % self.resource)
        return deleter(neutron_context, self.item)
