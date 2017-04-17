# Copyright 2017 Red Hat, Inc.
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

from tempest.lib import decorators
from tempest import test

from neutron.tests.tempest.scenario import base
from neutron.tests.tempest.scenario import test_dvr


class NetworkMigrationTestBase(base.BaseTempestTestCase,
                               test_dvr.NetworkTestMixin):
    credentials = ['primary', 'admin']
    force_tenant_isolation = False

    @classmethod
    @test.requires_ext(extension="dvr", service="network")
    @test.requires_ext(extension="l3-ha", service="network")
    def skip_checks(cls):
        super(NetworkMigrationTestBase, cls).skip_checks()

    def _check_update(self, router, is_dvr, is_ha):
        router = self.admin_manager.network_client.show_router(router['id'])
        self.assertEqual(is_dvr, router['router']['distributed'])
        self.assertEqual(is_ha, router['router']['ha'])

    def _test_migration(self, before_dvr, before_ha, after_dvr, after_ha):
        router = self.create_router_by_client(
            distributed=before_dvr, ha=before_ha,
            tenant_id=self.client.tenant_id, is_admin=True)

        self.setup_network_and_server(router=router)
        self._check_connectivity()

        self.admin_manager.network_client.update_router(
            router_id=router['id'], admin_state_up=False)
        self.admin_manager.network_client.update_router(
            router_id=router['id'], distributed=after_dvr, ha=after_ha)
        self._check_update(router, after_dvr, after_ha)

        self.admin_manager.network_client.update_router(
            router_id=router['id'], admin_state_up=True)
        self._check_connectivity()


class NetworkMigrationFromLegacy(NetworkMigrationTestBase):

    @decorators.idempotent_id('23724222-483a-4129-bc15-7a9278f3828b')
    def test_from_legacy_to_dvr(self):
        self._test_migration(before_dvr=False, before_ha=False,
                             after_dvr=True, after_ha=False)

    @decorators.idempotent_id('09d85102-994f-4ff9-bf3e-17051145ca12')
    def test_from_legacy_to_ha(self):
        self._test_migration(before_dvr=False, before_ha=False,
                             after_dvr=False, after_ha=True)

    @decorators.idempotent_id('fe169f2c-6ed3-4eb0-8afe-2d540c4b49e2')
    def test_from_legacy_to_dvr_ha(self):
        self._test_migration(before_dvr=False, before_ha=False,
                             after_dvr=True, after_ha=True)


class NetworkMigrationFromHA(NetworkMigrationTestBase):

    @decorators.idempotent_id('b4e68ac0-3b76-4306-ae8a-51cf4d363b22')
    def test_from_ha_to_legacy(self):
        self._test_migration(before_dvr=False, before_ha=True,
                             after_dvr=False, after_ha=False)

    @decorators.idempotent_id('42260eea-5d56-4d30-b62a-a62694dfe4d5')
    def test_from_ha_to_dvr(self):
        self._test_migration(before_dvr=False, before_ha=True,
                             after_dvr=True, after_ha=False)

    @decorators.idempotent_id('e4149576-248b-43fa-9d0b-a5c2f51967ce')
    def test_from_ha_to_dvr_ha(self):
        self._test_migration(before_dvr=False, before_ha=True,
                             after_dvr=True, after_ha=True)


class NetworkMigrationFromDVR(NetworkMigrationTestBase):

    @decorators.idempotent_id('e5cac02c-248d-4aac-bd5e-9d47c5197307')
    def test_from_dvr_to_legacy(self):
        self._test_migration(before_dvr=True, before_ha=False,
                             after_dvr=False, after_ha=False)

    @decorators.idempotent_id('a00d5ad7-8509-4bb0-bdd2-7f1ee052d1cd')
    def test_from_dvr_to_ha(self):
        self._test_migration(before_dvr=True, before_ha=False,
                             after_dvr=False, after_ha=True)

    @decorators.idempotent_id('25304a51-93a8-4cf3-9523-bce8b4eaecf8')
    def test_from_dvr_to_dvr_ha(self):
        self._test_migration(before_dvr=True, before_ha=False,
                             after_dvr=True, after_ha=True)


class NetworkMigrationFromDVRHA(NetworkMigrationTestBase):

    @decorators.idempotent_id('1be9b2e2-379c-40a4-a269-6687b81df691')
    def test_from_dvr_ha_to_legacy(self):
        self._test_migration(before_dvr=True, before_ha=True,
                             after_dvr=False, after_ha=False)

    @decorators.idempotent_id('55957267-4e84-4314-a2f7-7cd36a2df04b')
    def test_from_dvr_ha_to_ha(self):
        self._test_migration(before_dvr=True, before_ha=True,
                             after_dvr=False, after_ha=True)

    @decorators.idempotent_id('d6bedff1-72be-4a9a-8ea2-dc037cd838e0')
    def test_from_dvr_ha_to_dvr(self):
        self._test_migration(before_dvr=True, before_ha=True,
                             after_dvr=True, after_ha=False)
