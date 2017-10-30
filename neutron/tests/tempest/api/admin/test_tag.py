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
from neutron.tests.tempest import config


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
    @utils.requires_ext(extension="subnet_allocation", service="network")
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
    @utils.requires_ext(extension="router", service="network")
    def _create_resource(cls):
        router = cls.create_router(router_name='test')
        return router['id']

    @decorators.attr(type='smoke')
    @decorators.idempotent_id('b898ff92-dc33-4232-8ab9-2c6158c80d28')
    @utils.requires_ext(extension="tag-ext", service="network")
    def test_router_tags(self):
        self._test_tag_operations()


class TagSecGroupTestJSON(TagTestJSON):
    resource = 'security-groups'

    @classmethod
    @utils.requires_ext(extension="security-group", service="network")
    def _create_resource(cls):
        sec_group = cls.create_security_group(name='test')
        return sec_group['id']

    @decorators.attr(type='smoke')
    @decorators.idempotent_id('0f1a78eb-c5be-42cf-919d-2ce3621a51c2')
    @utils.requires_ext(extension="standard-attr-tag", service="network")
    def test_security_group_tags(self):
        self._test_tag_operations()


class TagFloatingIpTestJSON(TagTestJSON):
    resource = 'floatingips'

    @classmethod
    @utils.requires_ext(extension="router", service="network")
    def _create_resource(cls):
        cls.ext_net_id = config.CONF.network.public_network_id
        floatingip = cls.create_floatingip(cls.ext_net_id)
        return floatingip['id']

    @decorators.attr(type='smoke')
    @decorators.idempotent_id('53f6c2bf-e272-4e9e-b9a9-b165eb7be807')
    @utils.requires_ext(extension="standard-attr-tag", service="network")
    def test_floatingip_tags(self):
        self._test_tag_operations()


class TagQosPolicyTestJSON(TagTestJSON):
    resource = 'policies'

    @classmethod
    @utils.requires_ext(extension="qos", service="network")
    def _create_resource(cls):
        qos_policy = cls.create_qos_policy(name='test-policy', shared=True)
        return qos_policy['id']

    @decorators.attr(type='smoke')
    @decorators.idempotent_id('e9bac15e-c8bc-4317-8295-4bf1d8d522b8')
    @utils.requires_ext(extension="standard-attr-tag", service="network")
    def test_qos_policy_tags(self):
        self._test_tag_operations()


class TagTrunkTestJSON(TagTestJSON):
    resource = 'trunks'

    @classmethod
    @utils.requires_ext(extension="trunk", service="network")
    def _create_resource(cls):
        network = cls.create_network()
        parent_port = cls.create_port(network)
        trunk = cls.client.create_trunk(parent_port['id'], None)
        return trunk['trunk']['id']

    @classmethod
    def resource_cleanup(cls):
        cls.client.delete_trunk(cls.res_id)
        super(TagTrunkTestJSON, cls).resource_cleanup()

    @decorators.attr(type='smoke')
    @decorators.idempotent_id('4c63708b-c4c3-407c-8101-7a9593882f5f')
    @utils.requires_ext(extension="standard-attr-tag", service="network")
    def test_trunk_tags(self):
        self._test_tag_operations()


class TagFilterTestJSON(base.BaseAdminNetworkTest):
    credentials = ['primary', 'alt', 'admin']
    required_extensions = ['tag']

    @classmethod
    def resource_setup(cls):
        super(TagFilterTestJSON, cls).resource_setup()

        cls.res_ids = []
        for i in range(5):
            cls.res_ids.append(cls._create_resource())

        cls.client.update_tags(cls.resource, cls.res_ids[0], ['red'])
        cls.client.update_tags(cls.resource, cls.res_ids[1], ['red', 'blue'])
        cls.client.update_tags(cls.resource, cls.res_ids[2],
                               ['red', 'blue', 'green'])
        cls.client.update_tags(cls.resource, cls.res_ids[3], ['green'])
        # 5th resource: no tags

    @classmethod
    def setup_clients(cls):
        super(TagFilterTestJSON, cls).setup_clients()
        cls.client = cls.os_alt.network_client

    def _assertEqualResources(self, expected, res):
        expected = [self.res_ids[i] for i in expected]
        actual = [n['id'] for n in res if n['id'] in self.res_ids]
        self.assertEqual(set(expected), set(actual))

    def _test_filter_tags(self):
        # tags single
        filters = {'tags': 'red'}
        res = self._list_resource(filters)
        self._assertEqualResources([0, 1, 2], res)

        # tags multi
        filters = {'tags': 'red,blue'}
        res = self._list_resource(filters)
        self._assertEqualResources([1, 2], res)

        # tags-any single
        filters = {'tags-any': 'blue'}
        res = self._list_resource(filters)
        self._assertEqualResources([1, 2], res)

        # tags-any multi
        filters = {'tags-any': 'red,blue'}
        res = self._list_resource(filters)
        self._assertEqualResources([0, 1, 2], res)

        # not-tags single
        filters = {'not-tags': 'red'}
        res = self._list_resource(filters)
        self._assertEqualResources([3, 4], res)

        # not-tags multi
        filters = {'not-tags': 'red,blue'}
        res = self._list_resource(filters)
        self._assertEqualResources([0, 3, 4], res)

        # not-tags-any single
        filters = {'not-tags-any': 'blue'}
        res = self._list_resource(filters)
        self._assertEqualResources([0, 3, 4], res)

        # not-tags-any multi
        filters = {'not-tags-any': 'red,blue'}
        res = self._list_resource(filters)
        self._assertEqualResources([3, 4], res)


class TagFilterNetworkTestJSON(TagFilterTestJSON):
    resource = 'networks'

    @classmethod
    def _create_resource(cls):
        res = cls.create_network()
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
    def _create_resource(cls):
        network = cls.create_network()
        res = cls.create_subnet(network)
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
    def _create_resource(cls):
        network = cls.create_network()
        res = cls.create_port(network)
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
    @utils.requires_ext(extension="subnet_allocation", service="network")
    def _create_resource(cls):
        res = cls.create_subnetpool('subnetpool', default_prefixlen=24,
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
    @utils.requires_ext(extension="router", service="network")
    def _create_resource(cls):
        res = cls.create_router(router_name='test')
        return res['id']

    def _list_resource(self, filters):
        res = self.client.list_routers(**filters)
        return res[self.resource]

    @decorators.attr(type='smoke')
    @decorators.idempotent_id('cdd3f3ea-073d-4435-a6cb-826a4064193d')
    @utils.requires_ext(extension="tag-ext", service="network")
    def test_filter_router_tags(self):
        self._test_filter_tags()


class TagFilterSecGroupTestJSON(TagFilterTestJSON):
    resource = 'security-groups'

    @classmethod
    @utils.requires_ext(extension="security-group", service="network")
    def _create_resource(cls):
        sec_group = cls.create_security_group(name='test')
        return sec_group['id']

    def _list_resource(self, filters):
        res = self.client.list_security_groups(**filters)
        resource_key = self.resource.replace('-', '_')
        return res[resource_key]

    @decorators.attr(type='smoke')
    @decorators.idempotent_id('d4d1d681-0116-4800-9725-16cb88f8171a')
    @utils.requires_ext(extension="standard-attr-tag", service="network")
    def test_filter_security_group_tags(self):
        self._test_filter_tags()


class TagFilterFloatingIpTestJSON(TagFilterTestJSON):
    resource = 'floatingips'

    @classmethod
    @utils.requires_ext(extension="router", service="network")
    def _create_resource(cls):
        cls.ext_net_id = config.CONF.network.public_network_id
        floatingip = cls.create_floatingip(cls.ext_net_id)
        return floatingip['id']

    def _list_resource(self, filters):
        res = self.client.list_floatingips(**filters)
        return res[self.resource]

    @decorators.attr(type='smoke')
    @decorators.idempotent_id('01f00afc-dbec-432a-bfee-2a1f0510e7a8')
    @utils.requires_ext(extension="standard-attr-tag", service="network")
    def test_filter_floatingip_tags(self):
        self._test_filter_tags()


class TagFilterQosPolicyTestJSON(TagFilterTestJSON):
    resource = 'policies'

    @classmethod
    @utils.requires_ext(extension="qos", service="network")
    def _create_resource(cls):
        qos_policy = cls.create_qos_policy(name='test-policy', shared=True)
        return qos_policy['id']

    def _list_resource(self, filters):
        res = self.client.list_qos_policies(**filters)
        return res[self.resource]

    @decorators.attr(type='smoke')
    @decorators.idempotent_id('c2f9a6ae-2529-4cb9-a44b-b16f8ba27832')
    @utils.requires_ext(extension="standard-attr-tag", service="network")
    def test_filter_qos_policy_tags(self):
        self._test_filter_tags()


class TagFilterTrunkTestJSON(TagFilterTestJSON):
    resource = 'trunks'

    @classmethod
    @utils.requires_ext(extension="trunk", service="network")
    def _create_resource(cls):
        network = cls.create_network()
        parent_port = cls.create_port(network)
        trunk = cls.client.create_trunk(parent_port['id'], None)
        return trunk['trunk']['id']

    @classmethod
    def resource_cleanup(cls):
        for res_id in cls.res_ids:
            cls.client.delete_trunk(res_id)
        super(TagFilterTrunkTestJSON, cls).resource_cleanup()

    def _list_resource(self, filters):
        res = self.client.list_trunks(**filters)
        return res[self.resource]

    @decorators.attr(type='smoke')
    @decorators.idempotent_id('3fb3ca3a-8e3a-4565-ba73-16413d445e25')
    @utils.requires_ext(extension="standard-attr-tag", service="network")
    def test_filter_trunk_tags(self):
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
