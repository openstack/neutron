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

    def _make_query_string(self, tags, tags_any, not_tags, not_tags_any):
        filter_strings = []
        if tags:
            filter_strings.append("tags=" + ','.join(tags))
        if tags_any:
            filter_strings.append("tags-any=" + ','.join(tags_any))
        if not_tags:
            filter_strings.append("not-tags=" + ','.join(not_tags))
        if not_tags_any:
            filter_strings.append("not-tags-any=" + ','.join(not_tags_any))

        return '&'.join(filter_strings)

    def _get_tags_filter_resources(self, tags=None, tags_any=None,
                                   not_tags=None, not_tags_any=None):
        params = self._make_query_string(tags, tags_any, not_tags,
                                         not_tags_any)
        req = self._req('GET', self.resource, params=params)
        res = req.get_response(self.api)
        res = self.deserialize(self.fmt, res)
        return res[self.resource]


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


class TestNetworkTagFilter(TestTagApiBase):
    resource = 'networks'
    member = 'network'

    def setUp(self):
        super(TestNetworkTagFilter, self).setUp()
        self._prepare_network_tags()

    def _prepare_network_tags(self):
        res = self._make_network(self.fmt, 'net1', True)
        net1_id = res['network']['id']
        res = self._make_network(self.fmt, 'net2', True)
        net2_id = res['network']['id']
        res = self._make_network(self.fmt, 'net3', True)
        net3_id = res['network']['id']
        res = self._make_network(self.fmt, 'net4', True)
        net4_id = res['network']['id']
        res = self._make_network(self.fmt, 'net5', True)
        net5_id = res['network']['id']

        self._put_tags(net1_id, ['red'])
        self._put_tags(net2_id, ['red', 'blue'])
        self._put_tags(net3_id, ['red', 'blue', 'green'])
        self._put_tags(net4_id, ['green'])
        # net5: no tags
        tags = self._get_resource_tags(net5_id)
        self._assertEqualTags([], tags)

    def _assertEqualResources(self, expected, res):
        actual = [n['name'] for n in res]
        self.assertEqual(set(expected), set(actual))

    def test_filter_tags_single(self):
        res = self._get_tags_filter_resources(tags=['red'])
        self._assertEqualResources(['net1', 'net2', 'net3'], res)

    def test_filter_tags_multi(self):
        res = self._get_tags_filter_resources(tags=['red', 'blue'])
        self._assertEqualResources(['net2', 'net3'], res)

    def test_filter_tags_any_single(self):
        res = self._get_tags_filter_resources(tags_any=['blue'])
        self._assertEqualResources(['net2', 'net3'], res)

    def test_filter_tags_any_multi(self):
        res = self._get_tags_filter_resources(tags_any=['red', 'blue'])
        self._assertEqualResources(['net1', 'net2', 'net3'], res)

    def test_filter_not_tags_single(self):
        res = self._get_tags_filter_resources(not_tags=['red'])
        self._assertEqualResources(['net4', 'net5'], res)

    def test_filter_not_tags_multi(self):
        res = self._get_tags_filter_resources(not_tags=['red', 'blue'])
        self._assertEqualResources(['net1', 'net4', 'net5'], res)

    def test_filter_not_tags_any_single(self):
        res = self._get_tags_filter_resources(not_tags_any=['blue'])
        self._assertEqualResources(['net1', 'net4', 'net5'], res)

    def test_filter_not_tags_any_multi(self):
        res = self._get_tags_filter_resources(not_tags_any=['red', 'blue'])
        self._assertEqualResources(['net4', 'net5'], res)
