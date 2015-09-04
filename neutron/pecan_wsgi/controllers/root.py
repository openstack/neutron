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

import pecan
from pecan import request

from neutron.api import extensions
from neutron.api.views import versions as versions_view

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

    @expose()
    def _lookup(self, endpoint, *remainder):
        return CollectionsController(endpoint), remainder


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


class CollectionsController(object):

    def __init__(self, collection):
        self.collection = collection

    @expose()
    def _lookup(self, item, *remainder):
        return ItemController(item), remainder

    @expose(generic=True)
    def index(self, *args, **kwargs):
        return self.get(*args, **kwargs)

    def get(self, *args, **kwargs):
        # list request
        # TODO(kevinbenton): allow fields after policy enforced fields present
        kwargs.pop('fields', None)
        _listify = lambda x: x if isinstance(x, list) else [x]
        filters = {k: _listify(v) for k, v in kwargs.items()}
        lister = getattr(request.plugin, 'get_%s' % self.collection)
        return {self.collection: lister(request.context, filters=filters)}

    @when(index, method='POST')
    def post(self, *args, **kwargs):
        # TODO(kevinbenton): bulk!
        creator = getattr(request.plugin, 'create_%s' % request.resource_type)
        return {request.resource_type: creator(request.context,
                                               request.prepared_data)}


class ItemController(object):

    def __init__(self, item):
        self.item = item

    @expose(generic=True)
    def index(self, *args, **kwargs):
        return self.get()

    def get(self, *args, **kwargs):
        getter = getattr(request.plugin, 'get_%s' % request.resource_type)
        return {request.resource_type: getter(request.context, self.item)}

    @when(index, method='PUT')
    def put(self, *args, **kwargs):
        if request.member_action:
            member_action_method = getattr(request.plugin,
                                           request.member_action)
            return member_action_method(request.context, self.item,
                                        request.prepared_data)
        # TODO(kevinbenton): bulk?
        updater = getattr(request.plugin, 'update_%s' % request.resource_type)
        return updater(request.context, self.item, request.prepared_data)

    @when(index, method='DELETE')
    def delete(self):
        # TODO(kevinbenton): bulk?
        deleter = getattr(request.plugin, 'delete_%s' % request.resource_type)
        return deleter(request.context, self.item)
