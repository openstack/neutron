# Copyright (c) 2015 Mirantis, Inc.
# Copyright (c) 2015 Rackspace, Inc.
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

from oslo_log import log
import pecan
from pecan import request

from neutron._i18n import _, _LW
from neutron.api import extensions
from neutron.api.views import versions as versions_view
from neutron import manager

LOG = log.getLogger(__name__)
_VERSION_INFO = {}


def _load_version_info(version_info):
    assert version_info['id'] not in _VERSION_INFO
    _VERSION_INFO[version_info['id']] = version_info


def _get_version_info():
    return _VERSION_INFO.values()


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


class RootController(object):

    @expose(generic=True)
    def index(self):
        builder = versions_view.get_view_builder(pecan.request)
        versions = [builder.build(version) for version in _get_version_info()]
        return dict(versions=versions)

    @when(index, method='POST')
    @when(index, method='PUT')
    @when(index, method='DELETE')
    def not_supported(self):
        pecan.abort(405)


class ExtensionsController(object):

    @expose()
    def _lookup(self, alias, *remainder):
        return ExtensionController(alias), remainder

    @expose()
    def index(self):
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        exts = [extensions.ExtensionController._translate(ext)
                for ext in ext_mgr.extensions.values()]
        return {'extensions': exts}


class V2Controller(object):

    # Same data structure as neutron.api.versions.Versions for API backward
    # compatibility
    version_info = {
        'id': 'v2.0',
        'status': 'CURRENT'
    }
    _load_version_info(version_info)

    extensions = ExtensionsController()

    @expose(generic=True)
    def index(self):
        builder = versions_view.get_view_builder(pecan.request)
        return dict(version=builder.build(self.version_info))

    @when(index, method='POST')
    @when(index, method='PUT')
    @when(index, method='DELETE')
    def not_supported(self):
        pecan.abort(405)

    @expose()
    def _lookup(self, collection, *remainder):
        controller = manager.NeutronManager.get_controller_for_resource(
            collection)
        if not controller:
            LOG.warn(_LW("No controller found for: %s - returning response "
                         "code 404"), collection)
            pecan.abort(404)
        # Store resource name in pecan request context so that hooks can
        # leverage it if necessary
        request.context['resource'] = controller.resource
        return controller, remainder


# This controller cannot be specified directly as a member of RootController
# as its path is not a valid python identifier
pecan.route(RootController, 'v2.0', V2Controller())


class ExtensionController(object):

    def __init__(self, alias):
        self.alias = alias

    @expose()
    def index(self):
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        ext = ext_mgr.extensions.get(self.alias, None)
        if not ext:
            pecan.abort(
                404, detail=_("Extension with alias %s "
                              "does not exist") % self.alias)
        return {'extension': extensions.ExtensionController._translate(ext)}


class NeutronPecanController(object):

    def __init__(self, collection, resource):
        self.collection = collection
        self.resource = resource
        self.plugin = manager.NeutronManager.get_plugin_for_resource(
            self.resource)


class CollectionsController(NeutronPecanController):

    @expose()
    def _lookup(self, item, *remainder):
        return ItemController(self.resource, item), remainder

    @expose(generic=True)
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
        neutron_context = request.context.get('neutron_context')
        return {self.collection: lister(neutron_context, filters=filters)}

    @when(index, method='POST')
    def post(self, *args, **kwargs):
        # TODO(kevinbenton): emulated bulk!
        pecan.response.status = 201
        if request.bulk:
            method = 'create_%s_bulk' % self.resource
        else:
            method = 'create_%s' % self.resource
        creator = getattr(self.plugin, method)
        key = self.collection if request.bulk else self.resource
        neutron_context = request.context.get('neutron_context')
        return {key: creator(neutron_context, request.prepared_data)}


class ItemController(NeutronPecanController):

    def __init__(self, resource, item):
        super(ItemController, self).__init__(None, resource)
        self.item = item

    @expose(generic=True)
    def index(self, *args, **kwargs):
        return self.get()

    def get(self, *args, **kwargs):
        getter = getattr(self.plugin, 'get_%s' % self.resource)
        neutron_context = request.context.get('neutron_context')
        return {self.resource: getter(neutron_context, self.item)}

    @when(index, method='PUT')
    def put(self, *args, **kwargs):
        neutron_context = request.context.get('neutron_context')
        if request.member_action:
            member_action_method = getattr(self.plugin,
                                           request.member_action)
            return member_action_method(neutron_context, self.item,
                                        request.prepared_data)
        # TODO(kevinbenton): bulk?
        updater = getattr(self.plugin, 'update_%s' % self.resource)
        return updater(neutron_context, self.item, request.prepared_data)

    @when(index, method='DELETE')
    def delete(self):
        # TODO(kevinbenton): setting code could be in a decorator
        pecan.response.status = 204
        neutron_context = request.context.get('neutron_context')
        deleter = getattr(self.plugin, 'delete_%s' % self.resource)
        return deleter(neutron_context, self.item)
