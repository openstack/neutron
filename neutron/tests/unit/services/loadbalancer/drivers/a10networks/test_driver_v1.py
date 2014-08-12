# Copyright 2014, Doug Wiegley (dougwig), A10 Networks
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

import sys

import mock

from neutron import context
from neutron.db.loadbalancer import loadbalancer_db as lb_db
with mock.patch.dict(sys.modules, {'a10_neutron_lbaas': mock.Mock()}):
    from neutron.services.loadbalancer.drivers.a10networks import driver_v1
from neutron.tests.unit.db.loadbalancer import test_db_loadbalancer


def fake_model(id):
    return {
        'id': id,
        'tenant_id': "tennant-was-a-great-doctor"
    }


def fake_member(id):
    return {
        'id': id,
        'tenant_id': "vippyvip",
        'address': '1.1.1.1'
    }


class TestA10ThunderDriver(test_db_loadbalancer.LoadBalancerPluginDbTestCase):

    def setUp(self):
        super(TestA10ThunderDriver, self).setUp()
        self.context = context.get_admin_context()
        self.plugin = mock.Mock()
        self.driver = driver_v1.ThunderDriver(self.plugin)
        self.driver.a10 = mock.Mock()
        self.m = fake_model('p1')

    def test__hm_binding_count(self):
        n = self.driver._hm_binding_count(self.context, 'hm01')
        self.assertEqual(n, 0)

    def test__member_count(self):
        self.m = fake_member('mem1')
        n = self.driver._member_count(self.context, self.m)
        self.assertEqual(n, 0)

    def test__member_get_ip(self):
        self.m = fake_member('mem1')
        z = self.driver._member_get_ip(self.context, self.m, False)
        self.assertEqual(z, '1.1.1.1')
        z = self.driver._member_get_ip(self.context, self.m, True)
        self.assertEqual(z, '1.1.1.1')

    def test__pool_get_hm(self):
        self.driver._pool_get_hm(self.context, 'hm01')
        self.plugin.get_health_monitor.assert_called_once_with(
            self.context, 'hm01')

    def test__pool_get_tenant_id(self):
        z = self.driver._pool_get_tenant_id(self.context, 'pool1')
        self.assertEqual(z, '')

    def test__pool_get_vip_id(self):
        z = self.driver._pool_get_vip_id(self.context, 'pool1')
        self.assertEqual(z, '')

    def test__pool_total(self):
        n = self.driver._pool_total(self.context,
                                    tenant_id='whatareyoudoingdave')
        self.assertEqual(n, 0)

    def test__active(self):
        self.driver._active(self.context, 'vip', 'vip1')
        self.plugin.update_status.assert_called_once_with(
            self.context, lb_db.Vip, 'vip1', 'ACTIVE')

    def test__failed(self):
        self.driver._failed(self.context, 'vip', 'vip2-1-2')
        self.plugin.update_status.assert_called_once_with(
            self.context, lb_db.Vip, 'vip2-1-2', 'ERROR')

    def test__db_delete(self):
        self.driver._db_delete(self.context, 'pool', 'myid0101')
        self.plugin._delete_db_pool.assert_called_once_with(
            self.context, 'myid0101')

    def test__hm_active(self):
        self.driver._hm_active(self.context, 'hm01', 'pool1')
        self.plugin.update_pool_health_monitor.assert_called_once_with(
            self.context, 'hm01', 'pool1', 'ACTIVE')

    def test__hm_failed(self):
        self.driver._hm_failed(self.context, 'hm01', 'pool1')
        self.plugin.update_pool_health_monitor.assert_called_once_with(
            self.context, 'hm01', 'pool1', 'ERROR')

    def test__hm_db_delete(self):
        self.driver._hm_db_delete(self.context, 'hm01', 'pool2')
        self.plugin._delete_db_pool_health_monitor.assert_called_once_with(
            self.context, 'hm01', 'pool2')

    def test_create_vip(self):
        self.driver.create_vip(self.context, self.m)
        self.driver.a10.vip.create.assert_called_once_with(
            self.context, self.m)

    def test_update_vip(self):
        self.driver.update_vip(self.context, self.m, self.m)
        self.driver.a10.vip.update.assert_called_once_with(
            self.context, self.m, self.m)

    def test_delete_vip(self):
        self.driver.delete_vip(self.context, self.m)
        self.driver.a10.vip.delete.assert_called_once_with(
            self.context, self.m)

    def test_create_pool(self):
        self.driver.create_pool(self.context, self.m)
        self.driver.a10.pool.create.assert_called_once_with(
            self.context, self.m)

    def test_update_pool(self):
        self.driver.update_pool(self.context, self.m, self.m)
        self.driver.a10.pool.update.assert_called_once_with(
            self.context, self.m, self.m)

    def test_delete_pool(self):
        self.driver.delete_pool(self.context, self.m)
        self.driver.a10.pool.delete.assert_called_once_with(
            self.context, self.m)

    def test_stats(self):
        self.driver.stats(self.context, self.m['id'])
        self.driver.a10.pool.stats.assert_called_once_with(
            self.context, self.m['id'])

    def test_create_member(self):
        self.driver.create_member(self.context, self.m)
        self.driver.a10.member.create.assert_called_once_with(
            self.context, self.m)

    def test_update_member(self):
        self.driver.update_member(self.context, self.m, self.m)
        self.driver.a10.member.update.assert_called_once_with(
            self.context, self.m, self.m)

    def test_delete_member(self):
        self.driver.delete_member(self.context, self.m)
        self.driver.a10.member.delete.assert_called_once_with(
            self.context, self.m)

    def test_update_pool_health_monitor(self):
        self.driver.update_pool_health_monitor(self.context, self.m, self.m,
                                               'pool1')
        self.driver.a10.hm.update.assert_called_once_with(
            self.context, self.m, self.m, 'pool1')

    def test_create_pool_health_monitor(self):
        self.driver.create_pool_health_monitor(self.context, self.m, 'pool1')
        self.driver.a10.hm.create.assert_called_once_with(
            self.context, self.m, 'pool1')

    def test_delete_pool_health_monitor(self):
        self.driver.delete_pool_health_monitor(self.context, self.m, 'pool1')
        self.driver.a10.hm.delete.assert_called_once_with(
            self.context, self.m, 'pool1')
