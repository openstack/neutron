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

from neutron.api import extensions


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

    @expose()
    def _lookup(self, version, *remainder):
        if version == 'v2.0':
            return V2Controller(), remainder

    @expose(generic=True)
    def index(self):
        #TODO(kevinbenton): return a version list
        return dict(message='A neutron server')


class V2Controller(object):

    @expose()
    def _lookup(self, endpoint, *remainder):
        if endpoint == 'extensions':
            return ExtensionsController(), remainder
        return GeneralController(endpoint), remainder


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


class GeneralController(object):

    def __init__(self, token):
        self.token = token

    @expose()
    def _lookup(self, token, *remainder):
        return GeneralController(token), remainder

    @expose(generic=True)
    def index(self):
        return self.get()

    def get(self):
        return {'message': 'GET'}

    @when(index, method='PUT')
    def put(self, **kw):
        return {'message': 'PUT'}

    @when(index, method='POST')
    def post(self, **kw):
        return {'message': 'POST'}

    @when(index, method='DELETE')
    def delete(self):
        return {'message': 'DELETE'}
