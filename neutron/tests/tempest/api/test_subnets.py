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

from tempest.lib import decorators

from neutron.tests.tempest.api import base


class SubnetsSearchCriteriaTest(base.BaseSearchCriteriaTest):

    resource = 'subnet'

    list_kwargs = {'shared': False}

    @classmethod
    def resource_setup(cls):
        super(SubnetsSearchCriteriaTest, cls).resource_setup()
        net = cls.create_network(network_name='subnet-search-test-net')
        for name in cls.resource_names:
            cls.create_subnet(net, name=name)

    @decorators.idempotent_id('d2d61995-5dd5-4b93-bce7-3edefdb79563')
    def test_list_sorts_asc(self):
        self._test_list_sorts_asc()

    @decorators.idempotent_id('c3c6b0af-c4ac-4da0-b568-8d08ae550604')
    def test_list_sorts_desc(self):
        self._test_list_sorts_desc()

    @decorators.idempotent_id('b93063b3-f713-406e-bf93-e5738e09153c')
    def test_list_pagination(self):
        self._test_list_pagination()

    @decorators.idempotent_id('2ddd9aa6-de28-410f-9cbc-ce752893c407')
    def test_list_pagination_with_marker(self):
        self._test_list_pagination_with_marker()

    @decorators.idempotent_id('351183ef-6ed9-4d71-a9f2-a5ac049bd7ea')
    def test_list_pagination_with_href_links(self):
        self._test_list_pagination_with_href_links()

    @decorators.idempotent_id('dfaa20ca-6d84-4f26-962f-2fee4d247cd9')
    def test_list_pagination_page_reverse_asc(self):
        self._test_list_pagination_page_reverse_asc()

    @decorators.idempotent_id('40552213-3e12-4d6a-86f3-dda92f3de88c')
    def test_list_pagination_page_reverse_desc(self):
        self._test_list_pagination_page_reverse_desc()

    @decorators.idempotent_id('3cea9053-a731-4480-93ee-19b2c28a9ce4')
    def test_list_pagination_page_reverse_with_href_links(self):
        self._test_list_pagination_page_reverse_with_href_links()

    @decorators.idempotent_id('d851937c-9821-4b46-9d18-43e9077ecac0')
    def test_list_no_pagination_limit_0(self):
        self._test_list_no_pagination_limit_0()

    @decorators.idempotent_id('c0f9280b-9d81-4728-a967-6be22659d4c8')
    def test_list_validation_filters(self):
        self._test_list_validation_filters()
