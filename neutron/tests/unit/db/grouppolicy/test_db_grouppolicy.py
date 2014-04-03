# Copyright (c) 2012 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import contextlib

import webob.exc

from neutron.api import extensions as api_ext
from neutron.common import config
from neutron.db.grouppolicy import db_group_policy as gpdb
import neutron.extensions
from neutron.extensions import group_policy as gpolicy
from neutron.openstack.common import importutils
from neutron.plugins.common import constants
from neutron.tests.unit import test_db_plugin


DB_CORE_PLUGIN_KLASS = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'
DB_GP_PLUGIN_KLASS = (
    "neutron.db.grouppolicy.db_group_policy.GroupPolicyDbMixin"
)

extensions_path = ':'.join(neutron.extensions.__path__)


class GroupPolicyTestMixin(object):
    resource_prefix_map = dict(
        (k, constants.COMMON_PREFIXES[constants.GROUP_POLICY])
        for k in gpolicy.RESOURCE_ATTRIBUTE_MAP.keys()
    )

    def _get_test_endpoint_attrs(self, name='ep1'):
        attrs = {'name': name,
                 'tenant_id': self._tenant_id}

        return attrs

    def _create_endpoint(self, fmt, name, description,
                         expected_res_status=None, **kwargs):
        data = {'endpoint': {'name': name,
                             'description': description,
                             'tenant_id': self._tenant_id}}

        ep_req = self.new_create_request('endpoints', data, fmt)
        ep_res = ep_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(ep_res.status_int, expected_res_status)

        return ep_res

    @contextlib.contextmanager
    def endpoint(self, fmt=None, name='ep1', description=None,
                 no_delete=False, **kwargs):
        if not fmt:
            fmt = self.fmt

        res = self._create_endpoint(fmt, name, description, **kwargs)
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        ep = self.deserialize(fmt or self.fmt, res)
        try:
            yield ep
        finally:
            if not no_delete:
                self._delete('endpoints', ep['endpoint']['id'])


class GroupPolicyDbTestCase(GroupPolicyTestMixin,
                            test_db_plugin.NeutronDbPluginV2TestCase):

    def setUp(self, core_plugin=None, gp_plugin=None, ext_mgr=None):
        if not gp_plugin:
            gp_plugin = DB_GP_PLUGIN_KLASS
        service_plugins = {'gp_plugin_name': gp_plugin}

        gpdb.GroupPolicyDbMixin.supported_extension_aliases = ["group-policy"]
        super(GroupPolicyDbTestCase, self).setUp(
            ext_mgr=ext_mgr,
            service_plugins=service_plugins
        )

        if not ext_mgr:
            self.plugin = importutils.import_object(gp_plugin)
            ext_mgr = api_ext.PluginAwareExtensionManager(
                extensions_path,
                {constants.GROUP_POLICY: self.plugin}
            )
            app = config.load_paste_app('extensions_test_app')
            self.ext_api = api_ext.ExtensionMiddleware(app, ext_mgr=ext_mgr)


class TestGroupPolicy(GroupPolicyDbTestCase):

    def test_create_endpoint(self, **kwargs):
        name = "ep1"
        attrs = self._get_test_endpoint_attrs(name)

        with self.endpoint(name=name) as ep:
                for k, v in attrs.iteritems():
                    self.assertEqual(ep['endpoint'][k], v)


# TODO(Sumit): XML tests
