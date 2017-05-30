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

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from neutron.tests.tempest.api import base_routers as base


class RoutersTestHA(base.BaseRouterTest):

    required_extensions = ['router', 'l3-ha']

    @classmethod
    def resource_setup(cls):
        # The check above will pass if api_extensions=all, which does
        # not mean "l3-ha" extension itself is present.
        # Instead, we have to check whether "ha" is actually present by using
        # admin credentials to create router with ha=True attribute
        # and checking for BadRequest exception and that the resulting router
        # has a high availability attribute.
        super(RoutersTestHA, cls).resource_setup()
        name = data_utils.rand_name('pretest-check')
        router = cls.admin_client.create_router(name)
        if 'ha' not in router['router']:
            cls.admin_client.delete_router(router['router']['id'])
            msg = "'ha' attribute not found. HA Possibly not enabled"
            raise cls.skipException(msg)

    @decorators.idempotent_id('8abc177d-14f1-4018-9f01-589b299cbee1')
    def test_ha_router_creation(self):
        """
        Test uses administrative credentials to create a
        HA (High Availability) router using the ha=True.

        Acceptance
        The router is created and the "ha" attribute is set to True
        """
        name = data_utils.rand_name('router')
        router = self.admin_client.create_router(name, ha=True)
        self.addCleanup(self.admin_client.delete_router,
                        router['router']['id'])
        self.assertTrue(router['router']['ha'])

    @decorators.idempotent_id('97b5f7ef-2192-4fa3-901e-979cd5c1097a')
    def test_legacy_router_creation(self):
        """
        Test uses administrative credentials to create a
        SF (Single Failure) router using the ha=False.

        Acceptance
        The router is created and the "ha" attribute is
        set to False, thus making it a "Single Failure Router"
        as opposed to a "High Availability Router"
        """
        name = data_utils.rand_name('router')
        router = self.admin_client.create_router(name, ha=False)
        self.addCleanup(self.admin_client.delete_router,
                        router['router']['id'])
        self.assertFalse(router['router']['ha'])

    @decorators.idempotent_id('5a6bfe82-5b23-45a4-b027-5160997d4753')
    def test_legacy_router_update_to_ha(self):
        """
        Test uses administrative credentials to create a
        SF (Single Failure) router using the ha=False.
        Then it will "update" the router ha attribute to True

        Acceptance
        The router is created and the "ha" attribute is
        set to False. Once the router is updated, the ha
        attribute will be set to True
        """
        name = data_utils.rand_name('router')
        # router needs to be in admin state down in order to be upgraded to HA
        router = self.admin_client.create_router(name, ha=False,
                                                 admin_state_up=False)
        self.addCleanup(self.admin_client.delete_router,
                        router['router']['id'])
        self.assertFalse(router['router']['ha'])
        router = self.admin_client.update_router(router['router']['id'],
                                                 ha=True)
        self.assertTrue(router['router']['ha'])
