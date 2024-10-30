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

from neutron._i18n import _
from neutron.api import extensions
from neutron.pecan_wsgi.controllers import utils


class ExtensionsController:

    @utils.expose()
    def _lookup(self, alias, *remainder):
        return ExtensionController(alias), remainder

    @utils.expose(generic=True)
    def index(self):
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        exts = [extensions.ExtensionController._translate(ext)
                for ext in ext_mgr.extensions.values()]
        return {'extensions': exts}

    @utils.when(index, method='POST')
    @utils.when(index, method='PUT')
    @utils.when(index, method='DELETE')
    @utils.when(index, method='HEAD')
    @utils.when(index, method='PATCH')
    def not_supported(self):
        # NOTE(blogan): Normally we'd return 405 but the legacy extensions
        # controller returned 404.
        pecan.abort(404)


class ExtensionController:

    def __init__(self, alias):
        self.alias = alias

    @utils.expose(generic=True)
    def index(self):
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        ext = ext_mgr.extensions.get(self.alias, None)
        if not ext:
            pecan.abort(
                404, detail=_("Extension with alias %s "
                              "does not exist") % self.alias)
        return {'extension': extensions.ExtensionController._translate(ext)}

    @utils.when(index, method='POST')
    @utils.when(index, method='PUT')
    @utils.when(index, method='DELETE')
    @utils.when(index, method='HEAD')
    @utils.when(index, method='PATCH')
    def not_supported(self):
        # NOTE(blogan): Normally we'd return 405 but the legacy extensions
        # controller returned 404.
        pecan.abort(404)
