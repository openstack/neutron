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

from oslo_log import log as logging
import pecan
from pecan import request
import webob

from neutron._i18n import _
from neutron import manager
from neutron.pecan_wsgi.controllers import utils


LOG = logging.getLogger(__name__)


class ItemController(utils.NeutronPecanController):

    def __init__(self, resource, item, plugin=None, resource_info=None,
                 parent_resource=None, member_actions=None):
        super().__init__(None, resource, plugin=plugin,
                         resource_info=resource_info,
                         parent_resource=parent_resource,
                         member_actions=member_actions)
        self.item = item

    @utils.expose(generic=True)
    def index(self, *args, **kwargs):
        return self.get(*args, **kwargs)

    def get(self, *args, **kwargs):
        neutron_context = request.context['neutron_context']
        getter_args = [neutron_context, self.item]
        # NOTE(tonytan4ever): This implicitly forces the getter method
        # uses the parent_id as the last argument, thus easy for future
        # refactoring
        if 'parent_id' in request.context:
            getter_args.append(request.context['parent_id'])
        fields = request.context['query_params'].get('fields')
        return {self.resource: self.plugin_shower(*getter_args, fields=fields)}

    @utils.when(index, method='HEAD')
    @utils.when(index, method='POST')
    @utils.when(index, method='PATCH')
    def not_supported(self):
        pecan.abort(405)

    @utils.when(index, method='PUT')
    def put(self, *args, **kwargs):
        neutron_context = request.context['neutron_context']
        if "resources" not in request.context:
            msg = (_("Unable to find '%s' in request body") %
                   request.context['resource'])
            raise webob.exc.HTTPBadRequest(msg)
        resources = request.context['resources']
        # Bulk update is not supported, 'resources' always contains a single
        # elemenet
        data = {self.resource: resources[0]}
        updater_args = [neutron_context, self.item]
        if 'parent_id' in request.context:
            updater_args.append(request.context['parent_id'])
        updater_args.append(data)
        return {self.resource: self.plugin_updater(*updater_args)}

    @utils.when_delete(index)
    def delete(self):
        if request.body:
            msg = _("Request body is not supported in DELETE.")
            raise webob.exc.HTTPBadRequest(msg)
        neutron_context = request.context['neutron_context']
        deleter_args = [neutron_context, self.item]
        if 'parent_id' in request.context:
            deleter_args.append(request.context['parent_id'])
        return self.plugin_deleter(*deleter_args)

    @utils.expose()
    def _lookup(self, collection, *remainder):
        request.context['collection'] = collection
        collection_path = '/'.join([self.resource, collection])
        controller = manager.NeutronManager.get_controller_for_resource(
            collection_path)
        if not controller:
            if collection not in self._member_actions:
                LOG.warning("No controller found for: %s - returning "
                            "response code 404", collection)
                pecan.abort(404)
            # collection is a member action, so we create a new controller
            # for it.
            method = self._member_actions[collection]
            kwargs = {'plugin': self.plugin,
                      'resource_info': self.resource_info}
            if method == 'PUT':
                kwargs['update_action'] = collection
            elif method == 'GET':
                kwargs['show_action'] = collection
            controller = MemberActionController(
                self.resource, self.item, self, **kwargs)
        else:
            request.context['parent_id'] = request.context['resource_id']
        request.context['resource'] = controller.resource
        return controller, remainder


class CollectionsController(utils.NeutronPecanController):

    item_controller_class = ItemController

    @utils.expose()
    def _lookup(self, item, *remainder):
        # Store resource identifier in request context
        request.context['resource_id'] = item
        uri_identifier = '%s_id' % self.resource
        request.context['uri_identifiers'][uri_identifier] = item
        return (self.item_controller_class(
            self.resource, item, resource_info=self.resource_info,
            # NOTE(tonytan4ever): item needs to share the same
            # parent as collection
            parent_resource=self.parent,
            member_actions=self._member_actions,
            plugin=self.plugin), remainder)

    @utils.expose(generic=True)
    def index(self, *args, **kwargs):
        return self.get(*args, **kwargs)

    def get(self, *args, **kwargs):
        # NOTE(blogan): these are set in the FieldsAndFiltersHoook
        query_params = request.context['query_params']
        neutron_context = request.context['neutron_context']
        lister_args = [neutron_context]
        if 'parent_id' in request.context:
            lister_args.append(request.context['parent_id'])
        return {self.collection: self.plugin_lister(*lister_args,
                                                    **query_params)}

    @utils.when(index, method='HEAD')
    @utils.when(index, method='PATCH')
    @utils.when(index, method='PUT')
    @utils.when(index, method='DELETE')
    def not_supported(self):
        pecan.abort(405)

    @utils.when(index, method='POST')
    def post(self, *args, **kwargs):
        if 'resources' not in request.context:
            # user didn't specify any body, which is invalid for collections
            msg = (_("Unable to find '%s' in request body") %
                   request.context['resource'])
            raise webob.exc.HTTPBadRequest(msg)
        resources = request.context['resources']
        pecan.response.status = 201
        return self.create(resources)

    def create(self, resources):
        if request.context['is_bulk']:
            # Bulk!
            creator = self.plugin_bulk_creator
            key = self.collection
            data = {key: [{self.resource: res} for res in resources]}
            creator_kwargs = {self.collection: data}
        else:
            creator = self.plugin_creator
            key = self.resource
            data = {key: resources[0]}
            creator_kwargs = {self.resource: data}
        neutron_context = request.context['neutron_context']
        creator_args = [neutron_context]
        if 'parent_id' in request.context and self._parent_id_name:
            creator_kwargs[self._parent_id_name] = request.context['parent_id']
        return {key: creator(*creator_args, **creator_kwargs)}


class MemberActionController(ItemController):
    @property
    def plugin_shower(self):
        # NOTE(blogan): Do an explicit check for the _show_action because
        # pecan will see the plugin_shower property as a possible custom route
        # and try to evaluate it, which causes the code block to be executed.
        # If _show_action is None, getattr throws an exception and fails a
        # request.
        if self._show_action:
            return getattr(self.plugin, self._show_action)

    @property
    def plugin_updater(self):
        if self._update_action:
            return getattr(self.plugin, self._update_action)

    def __init__(self, resource, item, parent_controller, plugin=None,
                 resource_info=None, show_action=None, update_action=None):
        super().__init__(
            resource, item, plugin=plugin, resource_info=resource_info)
        self._show_action = show_action
        self._update_action = update_action
        self.parent_controller = parent_controller

    @utils.expose(generic=True)
    def index(self, *args, **kwargs):
        if not self._show_action:
            pecan.abort(405)
        neutron_context = request.context['neutron_context']
        # NOTE(blogan): The legacy wsgi code did not pass fields to the plugin
        # on GET member actions.  To maintain compatibility, we'll do the same.
        return self.plugin_shower(neutron_context, self.item)

    @utils.when(index, method='PUT')
    def put(self, *args, **kwargs):
        if not self._update_action:
            LOG.debug("Action %(action)s is not defined on resource "
                      "%(resource)s",
                      {'action': self._update_action,
                       'resource': self.resource})
            pecan.abort(405)
        neutron_context = request.context['neutron_context']
        LOG.debug("Processing member action %(action)s for resource "
                  "%(resource)s identified by %(item)s",
                  {'action': self._update_action,
                   'resource': self.resource,
                   'item': self.item})
        return self.plugin_updater(neutron_context, self.item,
                                   request.context['request_data'])

    @utils.when(index, method='HEAD')
    @utils.when(index, method='POST')
    @utils.when(index, method='PATCH')
    @utils.when(index, method='DELETE')
    def not_supported(self):
        return super().not_supported()
