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

from neutron_lib import context
from oslo_utils import uuidutils
import testscenarios

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.common import config
import neutron.extensions
from neutron.objects.qos import policy
from neutron.objects import trunk
from neutron.services.tag import tag_plugin
from neutron.tests import fake_notifier
from neutron.tests.unit.extensions import test_l3
from neutron.tests.unit.extensions import test_securitygroup


DB_PLUGIN_KLASS = 'neutron.tests.unit.extensions.test_tag.TestTagPlugin'

load_tests = testscenarios.load_tests_apply_scenarios
extensions_path = ':'.join(neutron.extensions.__path__)


class TestTagPlugin(test_securitygroup.SecurityGroupTestPlugin,
                    test_l3.TestL3NatBasePlugin):

    __native_pagination_support = True
    __native_sorting_support = True

    supported_extension_aliases = ["external-net", "security-group"]


class TestTagApiBase(test_securitygroup.SecurityGroupsTestCase,
                     test_l3.L3NatTestCaseMixin):
    scenarios = [
        ('Network Tag Test',
         dict(collection='networks',
              member='network')),
        ('Subnet Tag Test',
         dict(collection='subnets',
              member='subnet')),
        ('Port Tag Test',
         dict(collection='ports',
              member='port')),
        ('Subnetpool Tag Test',
         dict(collection='subnetpools',
              member='subnetpool')),
        ('Router Tag Test',
         dict(collection='routers',
              member='router')),
        ('Floatingip Tag Test',
         dict(collection='floatingips',
              member='floatingip')),
        ('Securitygroup Tag Test',
         dict(collection='security-groups',
              member='security_group')),
        ('QoS Policy Tag Test',
         dict(collection='policies',
              member='policy')),
        ('Trunk Tag Test',
         dict(collection='trunks',
              member='trunk')),
    ]

    def setUp(self):
        service_plugins = {
            'TAG': "neutron.services.tag.tag_plugin.TagPlugin",
            'router':
            "neutron.tests.unit.extensions.test_l3.TestL3NatServicePlugin"}
        super(TestTagApiBase, self).setUp(plugin=DB_PLUGIN_KLASS,
                                          service_plugins=service_plugins)
        plugin = tag_plugin.TagPlugin()
        l3_plugin = test_l3.TestL3NatServicePlugin()
        sec_plugin = test_securitygroup.SecurityGroupTestPlugin()
        ext_mgr = extensions.PluginAwareExtensionManager(
            extensions_path, {'router': l3_plugin, 'TAG': plugin,
                              'sec': sec_plugin}
        )
        ext_mgr.extend_resources("2.0", attributes.RESOURCE_ATTRIBUTE_MAP)
        app = config.load_paste_app('extensions_test_app')
        self.ext_api = extensions.ExtensionMiddleware(app, ext_mgr=ext_mgr)

    def _is_object(self):
        return self.collection in ['policies', 'trunks']

    def _prepare_make_resource(self):
        if self.collection == "floatingips":
            net = self._make_network(self.fmt, 'net1', True)
            self._set_net_external(net['network']['id'])
            self._make_subnet(self.fmt, net, '10.0.0.1', '10.0.0.0/24')
            info = {'network_id': net['network']['id']}
            self._make_router(self.fmt, None,
                              external_gateway_info=info)
            self.net = net['network']

    def _make_object(self):
        ctxt = context.get_admin_context()
        if self.collection == "policies":
            self.obj = policy.QosPolicy(context=ctxt,
                                        id=uuidutils.generate_uuid(),
                                        project_id='tenant', name='pol1',
                                        rules=[])
        elif self.collection == "trunks":
            net = self._make_network(self.fmt, 'net1', True)
            port = self._make_port(self.fmt, net['network']['id'])
            self.obj = trunk.Trunk(context=ctxt,
                                   id=uuidutils.generate_uuid(),
                                   project_id='tenant', name='',
                                   port_id=port['port']['id'])
        self.obj.create()
        return self.obj.id

    def _make_resource(self):
        if self._is_object():
            return self._make_object()

        if self.collection == "networks":
            res = self._make_network(self.fmt, 'net1', True)
        elif self.collection == "subnets":
            net = self._make_network(self.fmt, 'net1', True)
            res = self._make_subnet(self.fmt, net, '10.0.0.1', '10.0.0.0/24')
        elif self.collection == "ports":
            net = self._make_network(self.fmt, 'net1', True)
            res = self._make_port(self.fmt, net['network']['id'])
        elif self.collection == "subnetpools":
            res = self._make_subnetpool(self.fmt, ['10.0.0.0/8'],
                                        name='my pool', tenant_id="tenant")
        elif self.collection == "routers":
            res = self._make_router(self.fmt, None)
        elif self.collection == "floatingips":
            res = self._make_floatingip(self.fmt, self.net['id'])
        elif self.collection == "security-groups":
            res = self._make_security_group(self.fmt, 'sec1', '')
        return res[self.member]['id']

    def _get_object_tags(self):
        ctxt = context.get_admin_context()
        res = self.obj.get_object(ctxt, id=self.resource_id)
        return res.to_dict()['tags']

    def _get_resource_tags(self):
        if self._is_object():
            return self._get_object_tags()

        res = self._show(self.collection, self.resource_id)
        return res[self.member]['tags']

    def _put_tag(self, tag):
        req = self._req('PUT', self.collection, id=self.resource_id,
                        subresource='tags', sub_id=tag)
        return req.get_response(self.ext_api)

    def _put_tags(self, tags=None, body=None):
        if tags:
            body = {'tags': tags}
        elif body:
            body = body
        else:
            body = {}
        req = self._req('PUT', self.collection, data=body, id=self.resource_id,
                        subresource='tags')
        return req.get_response(self.ext_api)

    def _get_tag(self, tag):
        req = self._req('GET', self.collection, id=self.resource_id,
                        subresource='tags', sub_id=tag)
        return req.get_response(self.ext_api)

    def _delete_tag(self, tag):
        req = self._req('DELETE', self.collection, id=self.resource_id,
                        subresource='tags', sub_id=tag)
        return req.get_response(self.ext_api)

    def _delete_tags(self):
        req = self._req('DELETE', self.collection, id=self.resource_id,
                        subresource='tags')
        return req.get_response(self.ext_api)

    def _assertEqualTags(self, expected, actual):
        self.assertEqual(set(expected), set(actual))

    def _get_tags_filter_objects(self, tags, tags_any, not_tags,
                                 not_tags_any):
        filters = {}
        if tags:
            filters['tags'] = tags
        if tags_any:
            filters['tags-any'] = tags_any
        if not_tags:
            filters['not-tags'] = not_tags
        if not_tags_any:
            filters['not-tags-any'] = not_tags_any

        if self.collection == "policies":
            obj_class = policy.QosPolicy
        elif self.collection == "trunks":
            obj_class = trunk.Trunk
        ctxt = context.get_admin_context()
        res = obj_class.get_objects(ctxt, **filters)
        return [n.id for n in res]

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
        if self._is_object():
            return self._get_tags_filter_objects(tags, tags_any, not_tags,
                                                 not_tags_any)

        params = self._make_query_string(tags, tags_any, not_tags,
                                         not_tags_any)
        res = self._list(self.collection, query_params=params)
        return [n['id'] for n in res[self.collection.replace('-', '_')]]

    def _test_notification_report(self, expect_notify):
        notify = set(n['event_type'] for n in fake_notifier.NOTIFICATIONS)
        duplicated_notify = expect_notify & notify
        self.assertEqual(expect_notify, duplicated_notify)

        fake_notifier.reset()


class TestResourceTagApi(TestTagApiBase):

    def setUp(self):
        super(TestResourceTagApi, self).setUp()
        self._prepare_make_resource()
        self.resource_id = self._make_resource()

    def test_put_tag(self):
        expect_notify = set(['tag.create.start',
                             'tag.create.end'])
        res = self._put_tag('red')
        self.assertEqual(201, res.status_int)
        tags = self._get_resource_tags()
        self._assertEqualTags(['red'], tags)
        self._test_notification_report(expect_notify)
        res = self._put_tag('blue')
        self.assertEqual(201, res.status_int)
        tags = self._get_resource_tags()
        self._assertEqualTags(['red', 'blue'], tags)
        self._test_notification_report(expect_notify)

    def test_put_tag_exists(self):
        res = self._put_tag('blue')
        self.assertEqual(201, res.status_int)
        res = self._put_tag('blue')
        self.assertEqual(201, res.status_int)

    def test_put_tags(self):
        expect_notify = set(['tag.update.start',
                             'tag.update.end'])
        res = self._put_tags(['red', 'green'])
        self.assertEqual(200, res.status_int)
        tags = self._get_resource_tags()
        self._assertEqualTags(['red', 'green'], tags)
        self._test_notification_report(expect_notify)

    def test_put_invalid_tags(self):
        res = self._put_tags()
        self.assertEqual(400, res.status_int)
        res = self._put_tags(body=7)
        self.assertEqual(400, res.status_int)
        res = self._put_tags(body={'invalid': True})
        self.assertEqual(400, res.status_int)

    def test_put_tags_replace(self):
        res = self._put_tags(['red', 'green'])
        self.assertEqual(200, res.status_int)
        tags = self._get_resource_tags()
        self._assertEqualTags(['red', 'green'], tags)
        res = self._put_tags(['blue', 'red'])
        self.assertEqual(200, res.status_int)
        tags = self._get_resource_tags()
        self._assertEqualTags(['blue', 'red'], tags)

    def test_get_tag(self):
        res = self._put_tag('red')
        self.assertEqual(201, res.status_int)
        res = self._get_tag('red')
        self.assertEqual(204, res.status_int)

    def test_get_tag_notfound(self):
        res = self._put_tag('red')
        self.assertEqual(201, res.status_int)
        res = self._get_tag('green')
        self.assertEqual(404, res.status_int)

    def test_delete_tag(self):
        expect_notify = set(['tag.delete.start',
                             'tag.delete.end'])
        res = self._put_tags(['red', 'green'])
        self.assertEqual(200, res.status_int)
        res = self._delete_tag('red')
        self.assertEqual(204, res.status_int)
        tags = self._get_resource_tags()
        self._assertEqualTags(['green'], tags)
        self._test_notification_report(expect_notify)

    def test_delete_tag_notfound(self):
        res = self._put_tags(['red', 'green'])
        self.assertEqual(200, res.status_int)
        res = self._delete_tag('blue')
        self.assertEqual(404, res.status_int)

    def test_delete_tags(self):
        expect_notify = set(['tag.delete_all.start',
                             'tag.delete_all.end'])
        res = self._put_tags(['red', 'green'])
        self.assertEqual(200, res.status_int)
        res = self._delete_tags()
        self.assertEqual(204, res.status_int)
        tags = self._get_resource_tags()
        self._assertEqualTags([], tags)
        self._test_notification_report(expect_notify)


class TestResourceTagFilter(TestTagApiBase):

    def setUp(self):
        super(TestResourceTagFilter, self).setUp()
        self._prepare_resource_tags()

    def _make_tags(self, resource_id, tags):
        body = {'tags': tags}
        req = self._req('PUT', self.collection, data=body, id=resource_id,
                        subresource='tags')
        return req.get_response(self.ext_api)

    def _prepare_resource_tags(self):
        self._prepare_make_resource()
        self.res1 = self._make_resource()
        self.res2 = self._make_resource()
        self.res3 = self._make_resource()
        self.res4 = self._make_resource()
        self.res5 = self._make_resource()
        self.res_ids = [self.res1, self.res2, self.res3, self.res4, self.res5]

        self._make_tags(self.res1, ['red'])
        self._make_tags(self.res2, ['red', 'blue'])
        self._make_tags(self.res3, ['red', 'blue', 'green'])
        self._make_tags(self.res4, ['green'])
        # res5: no tags

    def _assertEqualResources(self, expected, resources):
        actual = [n for n in resources if n in self.res_ids]
        self.assertEqual(set(expected), set(actual))

    def test_filter_tags_single(self):
        resources = self._get_tags_filter_resources(tags=['red'])
        self._assertEqualResources([self.res1, self.res2, self.res3],
                                   resources)

    def test_filter_tags_multi(self):
        resources = self._get_tags_filter_resources(tags=['red', 'blue'])
        self._assertEqualResources([self.res2, self.res3], resources)

    def test_filter_tags_any_single(self):
        resources = self._get_tags_filter_resources(tags_any=['blue'])
        self._assertEqualResources([self.res2, self.res3], resources)

    def test_filter_tags_any_multi(self):
        resources = self._get_tags_filter_resources(tags_any=['red', 'blue'])
        self._assertEqualResources([self.res1, self.res2, self.res3],
                                   resources)

    def test_filter_not_tags_single(self):
        resources = self._get_tags_filter_resources(not_tags=['red'])
        self._assertEqualResources([self.res4, self.res5], resources)

    def test_filter_not_tags_multi(self):
        resources = self._get_tags_filter_resources(not_tags=['red', 'blue'])
        self._assertEqualResources([self.res1, self.res4, self.res5],
                                   resources)

    def test_filter_not_tags_any_single(self):
        resources = self._get_tags_filter_resources(not_tags_any=['blue'])
        self._assertEqualResources([self.res1, self.res4, self.res5],
                                   resources)

    def test_filter_not_tags_any_multi(self):
        resources = self._get_tags_filter_resources(not_tags_any=['red',
                                                                  'blue'])
        self._assertEqualResources([self.res4, self.res5], resources)
