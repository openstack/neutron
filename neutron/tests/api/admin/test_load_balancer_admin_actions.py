# Copyright 2014 Mirantis.inc
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

from tempest_lib.common.utils import data_utils

from neutron.tests.api import base
from neutron.tests.tempest import test


class LoadBalancerAdminTestJSON(base.BaseAdminNetworkTest):

    """
    Test admin actions for load balancer.

    Create VIP for another tenant
    Create health monitor for another tenant
    """

    @classmethod
    def resource_setup(cls):
        super(LoadBalancerAdminTestJSON, cls).resource_setup()
        if not test.is_extension_enabled('lbaas', 'network'):
            msg = "lbaas extension not enabled."
            raise cls.skipException(msg)
        cls.force_tenant_isolation = True
        manager = cls.get_client_manager()
        cls.client = manager.network_client
        cls.tenant_id = cls.isolated_creds.get_primary_creds().tenant_id
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.pool = cls.create_pool(data_utils.rand_name('pool-'),
                                   "ROUND_ROBIN", "HTTP", cls.subnet)

    @test.attr(type='smoke')
    @test.idempotent_id('6b0a20d8-4fcd-455e-b54f-ec4db5199518')
    def test_create_vip_as_admin_for_another_tenant(self):
        name = data_utils.rand_name('vip-')
        body = self.admin_client.create_pool(
            name=data_utils.rand_name('pool-'),
            lb_method="ROUND_ROBIN",
            protocol="HTTP",
            subnet_id=self.subnet['id'],
            tenant_id=self.tenant_id)
        pool = body['pool']
        self.addCleanup(self.admin_client.delete_pool, pool['id'])
        body = self.admin_client.create_vip(name=name,
                                            protocol="HTTP",
                                            protocol_port=80,
                                            subnet_id=self.subnet['id'],
                                            pool_id=pool['id'],
                                            tenant_id=self.tenant_id)
        vip = body['vip']
        self.addCleanup(self.admin_client.delete_vip, vip['id'])
        self.assertIsNotNone(vip['id'])
        self.assertEqual(self.tenant_id, vip['tenant_id'])
        body = self.client.show_vip(vip['id'])
        show_vip = body['vip']
        self.assertEqual(vip['id'], show_vip['id'])
        self.assertEqual(vip['name'], show_vip['name'])

    @test.attr(type='smoke')
    @test.idempotent_id('74552cfc-ab78-4fb6-825b-f67bca379921')
    def test_create_health_monitor_as_admin_for_another_tenant(self):
        body = (
            self.admin_client.create_health_monitor(delay=4,
                                                    max_retries=3,
                                                    type="TCP",
                                                    timeout=1,
                                                    tenant_id=self.tenant_id))
        health_monitor = body['health_monitor']
        self.addCleanup(self.admin_client.delete_health_monitor,
                        health_monitor['id'])
        self.assertIsNotNone(health_monitor['id'])
        self.assertEqual(self.tenant_id, health_monitor['tenant_id'])
        body = self.client.show_health_monitor(health_monitor['id'])
        show_health_monitor = body['health_monitor']
        self.assertEqual(health_monitor['id'], show_health_monitor['id'])

    @test.attr(type='smoke')
    @test.idempotent_id('266a192d-3c22-46c4-a8fb-802450301e82')
    def test_create_pool_from_admin_user_other_tenant(self):
        body = self.admin_client.create_pool(
            name=data_utils.rand_name('pool-'),
            lb_method="ROUND_ROBIN",
            protocol="HTTP",
            subnet_id=self.subnet['id'],
            tenant_id=self.tenant_id)
        pool = body['pool']
        self.addCleanup(self.admin_client.delete_pool, pool['id'])
        self.assertIsNotNone(pool['id'])
        self.assertEqual(self.tenant_id, pool['tenant_id'])

    @test.attr(type='smoke')
    @test.idempotent_id('158bb272-b9ed-4cfc-803c-661dac46f783')
    def test_create_member_from_admin_user_other_tenant(self):
        body = self.admin_client.create_member(address="10.0.9.47",
                                               protocol_port=80,
                                               pool_id=self.pool['id'],
                                               tenant_id=self.tenant_id)
        member = body['member']
        self.addCleanup(self.admin_client.delete_member, member['id'])
        self.assertIsNotNone(member['id'])
        self.assertEqual(self.tenant_id, member['tenant_id'])
