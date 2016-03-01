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

from neutron.api import extensions
from neutron.common import config
import neutron.extensions
from neutron.services.tag import tag_plugin
from neutron.tests.unit.db import test_db_base_plugin_v2


extensions_path = ':'.join(neutron.extensions.__path__)


class TestTagApiBase(test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    def setUp(self):
        service_plugins = {'TAG': "neutron.services.tag.tag_plugin.TagPlugin"}
        super(TestTagApiBase, self).setUp(service_plugins=service_plugins)
        plugin = tag_plugin.TagPlugin()
        ext_mgr = extensions.PluginAwareExtensionManager(
            extensions_path, {'TAG': plugin}
        )
        app = config.load_paste_app('extensions_test_app')
        self.ext_api = extensions.ExtensionMiddleware(app, ext_mgr=ext_mgr)

    def _get_resource_tags(self, resource_id):
        res = self._show(self.resource, resource_id)
        return res[self.member]['tags']

    def _put_tag(self, resource_id, tag):
        req = self._req('PUT', self.resource, id=resource_id,
                        subresource='tags', sub_id=tag)
        return req.get_response(self.ext_api)

    def _put_tags(self, resource_id, tags):
        body = {'tags': tags}
        req = self._req('PUT', self.resource, data=body, id=resource_id,
                        subresource='tags')
        return req.get_response(self.ext_api)

    def _get_tag(self, resource_id, tag):
        req = self._req('GET', self.resource, id=resource_id,
                        subresource='tags', sub_id=tag)
        return req.get_response(self.ext_api)

    def _delete_tag(self, resource_id, tag):
        req = self._req('DELETE', self.resource, id=resource_id,
                        subresource='tags', sub_id=tag)
        return req.get_response(self.ext_api)

    def _delete_tags(self, resource_id):
        req = self._req('DELETE', self.resource, id=resource_id,
                        subresource='tags')
        return req.get_response(self.ext_api)

    def _assertEqualTags(self, expected, actual):
        self.assertEqual(set(expected), set(actual))


class TestNetworkTagApi(TestTagApiBase):
    resource = 'networks'
    member = 'network'

    def test_put_tag(self):
        with self.network() as net:
            net_id = net['network']['id']
            res = self._put_tag(net_id, 'red')
            self.assertEqual(201, res.status_int)
            tags = self._get_resource_tags(net_id)
            self._assertEqualTags(['red'], tags)
            res = self._put_tag(net_id, 'blue')
            self.assertEqual(201, res.status_int)
            tags = self._get_resource_tags(net_id)
            self._assertEqualTags(['red', 'blue'], tags)

    def test_put_tag_exists(self):
        with self.network() as net:
            net_id = net['network']['id']
            res = self._put_tag(net_id, 'blue')
            self.assertEqual(201, res.status_int)
            res = self._put_tag(net_id, 'blue')
            self.assertEqual(201, res.status_int)

    def test_put_tags(self):
        with self.network() as net:
            net_id = net['network']['id']
            res = self._put_tags(net_id, ['red', 'green'])
            self.assertEqual(200, res.status_int)
            tags = self._get_resource_tags(net_id)
            self._assertEqualTags(['red', 'green'], tags)

    def test_put_tags_replace(self):
        with self.network() as net:
            net_id = net['network']['id']
            res = self._put_tags(net_id, ['red', 'green'])
            self.assertEqual(200, res.status_int)
            tags = self._get_resource_tags(net_id)
            self._assertEqualTags(['red', 'green'], tags)
            res = self._put_tags(net_id, ['blue', 'red'])
            self.assertEqual(200, res.status_int)
            tags = self._get_resource_tags(net_id)
            self._assertEqualTags(['blue', 'red'], tags)

    def test_get_tag(self):
        with self.network() as net:
            net_id = net['network']['id']
            res = self._put_tag(net_id, 'red')
            self.assertEqual(201, res.status_int)
            res = self._get_tag(net_id, 'red')
            self.assertEqual(204, res.status_int)

    def test_get_tag_notfound(self):
        with self.network() as net:
            net_id = net['network']['id']
            res = self._put_tag(net_id, 'red')
            self.assertEqual(201, res.status_int)
            res = self._get_tag(net_id, 'green')
            self.assertEqual(404, res.status_int)

    def test_delete_tag(self):
        with self.network() as net:
            net_id = net['network']['id']
            res = self._put_tags(net_id, ['red', 'green'])
            self.assertEqual(200, res.status_int)
            res = self._delete_tag(net_id, 'red')
            self.assertEqual(204, res.status_int)
            tags = self._get_resource_tags(net_id)
            self._assertEqualTags(['green'], tags)

    def test_delete_tag_notfound(self):
        with self.network() as net:
            net_id = net['network']['id']
            res = self._put_tags(net_id, ['red', 'green'])
            self.assertEqual(200, res.status_int)
            res = self._delete_tag(net_id, 'blue')
            self.assertEqual(404, res.status_int)

    def test_delete_tags(self):
        with self.network() as net:
            net_id = net['network']['id']
            res = self._put_tags(net_id, ['red', 'green'])
            self.assertEqual(200, res.status_int)
            res = self._delete_tags(net_id)
            self.assertEqual(204, res.status_int)
            tags = self._get_resource_tags(net_id)
            self._assertEqualTags([], tags)
