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

from tempest.common import utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from neutron.tests.tempest.api import base


class TagTestJSON(base.BaseAdminNetworkTest):

    required_extensions = ['tag']

    @classmethod
    def resource_setup(cls):
        super(TagTestJSON, cls).resource_setup()
        cls.res_id = cls._create_resource()

    def _get_and_compare_tags(self, tags):
        res_body = self.client.get_tags(self.resource, self.res_id)
        self.assertItemsEqual(tags, res_body['tags'])

    def _test_tag_operations(self):
        # create and get tags
        tags = ['red', 'blue']
        res_body = self.client.update_tags(self.resource, self.res_id, tags)
        self.assertItemsEqual(tags, res_body['tags'])
        self._get_and_compare_tags(tags)

        # add a tag
        self.client.update_tag(self.resource, self.res_id, 'green')
        self._get_and_compare_tags(['red', 'blue', 'green'])

        # update tag exist
        self.client.update_tag(self.resource, self.res_id, 'red')
        self._get_and_compare_tags(['red', 'blue', 'green'])

        # add a tag with a dot
        self.client.update_tag(self.resource, self.res_id, 'black.or.white')
        self._get_and_compare_tags(['red', 'blue', 'green', 'black.or.white'])

        # replace tags
        tags = ['red', 'yellow', 'purple']
        res_body = self.client.update_tags(self.resource, self.res_id, tags)
        self.assertItemsEqual(tags, res_body['tags'])
        self._get_and_compare_tags(tags)

        # get tag
        self.client.get_tag(self.resource, self.res_id, 'red')

        # get tag not exist
        self.assertRaises(lib_exc.NotFound, self.client.get_tag,
                          self.resource, self.res_id, 'green')

        # delete tag
        self.client.delete_tag(self.resource, self.res_id, 'red')
        self._get_and_compare_tags(['yellow', 'purple'])

        # delete tag not exist
        self.assertRaises(lib_exc.NotFound, self.client.delete_tag,
                          self.resource, self.res_id, 'green')

        # delete tags
        self.client.delete_tags(self.resource, self.res_id)
        self._get_and_compare_tags([])


class TagNetworkTestJSON(TagTestJSON):
    resource = 'networks'

    @classmethod
    def _create_resource(cls):
        network = cls.create_network()
        return network['id']

    @decorators.attr(type='smoke')
    @decorators.idempotent_id('5621062d-fbfb-4437-9d69-138c78ea4188')
    def test_network_tags(self):
        self._test_tag_operations()


class TagSubnetTestJSON(TagTestJSON):
    resource = 'subnets'

    @classmethod
    def _create_resource(cls):
        network = cls.create_network()
        subnet = cls.create_subnet(network)
        return subnet['id']

    @decorators.attr(type='smoke')
    @decorators.idempotent_id('2805aabf-a94c-4e70-a0b2-9814f06beb03')
    @utils.requires_ext(extension="tag-ext", service="network")
    def test_subnet_tags(self):
        self._test_tag_operations()


class TagPortTestJSON(TagTestJSON):
    resource = 'ports'

    @classmethod
    def _create_resource(cls):
        network = cls.create_network()
        port = cls.create_port(network)
        return port['id']

    @decorators.attr(type='smoke')
    @decorators.idempotent_id('c7c44f2c-edb0-4ebd-a386-d37cec155c34')
    @utils.requires_ext(extension="tag-ext", service="network")
    def test_port_tags(self):
        self._test_tag_operations()


class TagSubnetPoolTestJSON(TagTestJSON):
    resource = 'subnetpools'

    @classmethod
    def _create_resource(cls):
        subnetpool = cls.create_subnetpool('subnetpool', default_prefixlen=24,
                                           prefixes=['10.0.0.0/8'])
        return subnetpool['id']

    @decorators.attr(type='smoke')
    @decorators.idempotent_id('bdc1c24b-c0b5-4835-953c-8f67dc11edfe')
    @utils.requires_ext(extension="tag-ext", service="network")
    def test_subnetpool_tags(self):
        self._test_tag_operations()


class TagRouterTestJSON(TagTestJSON):
    resource = 'routers'

    @classmethod
    def _create_resource(cls):
        router = cls.create_router(router_name='test')
        return router['id']

    @decorators.attr(type='smoke')
    @decorators.idempotent_id('b898ff92-dc33-4232-8ab9-2c6158c80d28')
    @utils.requires_ext(extension="router", service="network")
    @utils.requires_ext(extension="tag-ext", service="network")
    def test_router_tags(self):
        self._test_tag_operations()


class TagFilterTestJSON(base.BaseAdminNetworkTest):
    credentials = ['primary', 'alt', 'admin']
    required_extensions = ['tag']

    @classmethod
    def resource_setup(cls):
        super(TagFilterTestJSON, cls).resource_setup()

        res1_id = cls._create_resource('tag-res1')
        res2_id = cls._create_resource('tag-res2')
        res3_id = cls._create_resource('tag-res3')
        res4_id = cls._create_resource('tag-res4')
        # tag-res5: a resource without tags
        cls._create_resource('tag-res5')

        cls.client.update_tags(cls.resource, res1_id, ['red'])
        cls.client.update_tags(cls.resource, res2_id, ['red', 'blue'])
        cls.client.update_tags(cls.resource, res3_id,
                               ['red', 'blue', 'green'])
        cls.client.update_tags(cls.resource, res4_id, ['green'])

    @classmethod
    def setup_clients(cls):
        super(TagFilterTestJSON, cls).setup_clients()
        cls.client = cls.os_alt.network_client

    def _assertEqualResources(self, expected, res):
        actual = [n['name'] for n in res if n['name'].startswith('tag-res')]
        self.assertEqual(set(expected), set(actual))

    def _test_filter_tags(self):
        # tags single
        filters = {'tags': 'red'}
        res = self._list_resource(filters)
        self._assertEqualResources(['tag-res1', 'tag-res2', 'tag-res3'], res)

        # tags multi
        filters = {'tags': 'red,blue'}
        res = self._list_resource(filters)
        self._assertEqualResources(['tag-res2', 'tag-res3'], res)

        # tags-any single
        filters = {'tags-any': 'blue'}
        res = self._list_resource(filters)
        self._assertEqualResources(['tag-res2', 'tag-res3'], res)

        # tags-any multi
        filters = {'tags-any': 'red,blue'}
        res = self._list_resource(filters)
        self._assertEqualResources(['tag-res1', 'tag-res2', 'tag-res3'], res)

        # not-tags single
        filters = {'not-tags': 'red'}
        res = self._list_resource(filters)
        self._assertEqualResources(['tag-res4', 'tag-res5'], res)

        # not-tags multi
        filters = {'not-tags': 'red,blue'}
        res = self._list_resource(filters)
        self._assertEqualResources(['tag-res1', 'tag-res4', 'tag-res5'], res)

        # not-tags-any single
        filters = {'not-tags-any': 'blue'}
        res = self._list_resource(filters)
        self._assertEqualResources(['tag-res1', 'tag-res4', 'tag-res5'], res)

        # not-tags-any multi
        filters = {'not-tags-any': 'red,blue'}
        res = self._list_resource(filters)
        self._assertEqualResources(['tag-res4', 'tag-res5'], res)


class TagFilterNetworkTestJSON(TagFilterTestJSON):
    resource = 'networks'

    @classmethod
    def _create_resource(cls, name):
        res = cls.create_network(network_name=name)
        return res['id']

    def _list_resource(self, filters):
        res = self.client.list_networks(**filters)
        return res[self.resource]

    @decorators.attr(type='smoke')
    @decorators.idempotent_id('a66b5cca-7db2-40f5-a33d-8ac9f864e53e')
    def test_filter_network_tags(self):
        self._test_filter_tags()


class TagFilterSubnetTestJSON(TagFilterTestJSON):
    resource = 'subnets'

    @classmethod
    def _create_resource(cls, name):
        network = cls.create_network()
        res = cls.create_subnet(network, name=name)
        return res['id']

    def _list_resource(self, filters):
        res = self.client.list_subnets(**filters)
        return res[self.resource]

    @decorators.attr(type='smoke')
    @decorators.idempotent_id('dd8f9ba7-bcf6-496f-bead-714bd3daac10')
    @utils.requires_ext(extension="tag-ext", service="network")
    def test_filter_subnet_tags(self):
        self._test_filter_tags()


class TagFilterPortTestJSON(TagFilterTestJSON):
    resource = 'ports'

    @classmethod
    def _create_resource(cls, name):
        network = cls.create_network()
        res = cls.create_port(network, name=name)
        return res['id']

    def _list_resource(self, filters):
        res = self.client.list_ports(**filters)
        return res[self.resource]

    @decorators.attr(type='smoke')
    @decorators.idempotent_id('09c036b8-c8d0-4bee-b776-7f4601512898')
    @utils.requires_ext(extension="tag-ext", service="network")
    def test_filter_port_tags(self):
        self._test_filter_tags()


class TagFilterSubnetpoolTestJSON(TagFilterTestJSON):
    resource = 'subnetpools'

    @classmethod
    def _create_resource(cls, name):
        res = cls.create_subnetpool(name, default_prefixlen=24,
                                    prefixes=['10.0.0.0/8'])
        return res['id']

    def _list_resource(self, filters):
        res = self.client.list_subnetpools(**filters)
        return res[self.resource]

    @decorators.attr(type='smoke')
    @decorators.idempotent_id('16ae7ad2-55c2-4821-9195-bfd04ab245b7')
    @utils.requires_ext(extension="tag-ext", service="network")
    def test_filter_subnetpool_tags(self):
        self._test_filter_tags()


class TagFilterRouterTestJSON(TagFilterTestJSON):
    resource = 'routers'

    @classmethod
    def _create_resource(cls, name):
        res = cls.create_router(router_name=name)
        return res['id']

    def _list_resource(self, filters):
        res = self.client.list_routers(**filters)
        return res[self.resource]

    @decorators.attr(type='smoke')
    @decorators.idempotent_id('cdd3f3ea-073d-4435-a6cb-826a4064193d')
    @utils.requires_ext(extension="tag-ext", service="network")
    def test_filter_router_tags(self):
        self._test_filter_tags()


class UpdateTagsTest(base.BaseAdminNetworkTest):

    required_extensions = ['tag']

    def _get_and_compare_tags(self, tags, res_id):
        # nothing specific about networks here, just a resource that is
        # available in all setups
        res_body = self.client.get_tags('networks', res_id)
        self.assertItemsEqual(tags, res_body['tags'])

    @decorators.attr(type='smoke')
    @decorators.idempotent_id('74c56fb1-a3b1-4a62-a8d2-d04dca6bd4cd')
    def test_update_tags_affects_only_updated_resource(self):
        res1 = self.create_network()
        res2 = self.create_network()

        self.client.update_tags('networks', res1['id'], ['red', 'blue'])
        self._get_and_compare_tags(['red', 'blue'], res1['id'])

        self.client.update_tags('networks', res2['id'], ['red'])
        self._get_and_compare_tags(['red'], res2['id'])

        self.client.update_tags('networks', res2['id'], [])
        self._get_and_compare_tags([], res2['id'])

        # check that updates on res2 hasn't dropped tags from res1
        self._get_and_compare_tags(['red', 'blue'], res1['id'])
