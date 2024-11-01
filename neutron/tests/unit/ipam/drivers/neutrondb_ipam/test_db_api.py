# Copyright 2015 OpenStack Foundation.
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

from neutron_lib import context
from oslo_utils import uuidutils

from neutron.ipam.drivers.neutrondb_ipam import db_api
from neutron.objects import ipam as ipam_obj
from neutron.tests.unit import testlib_api

CORE_PLUGIN = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'


class TestIpamSubnetManager(testlib_api.SqlTestCase):
    """Test case for SubnetManager DB helper class"""

    def setUp(self):
        super().setUp()
        self.setup_coreplugin(core_plugin=CORE_PLUGIN)
        self.ctx = context.get_admin_context()
        self.neutron_subnet_id = uuidutils.generate_uuid()
        self.ipam_subnet_id = uuidutils.generate_uuid()
        self.subnet_ip = '1.2.3.4'
        self.single_pool = ('1.2.3.4', '1.2.3.10')
        self.multi_pool = (('1.2.3.2', '1.2.3.12'), ('1.2.3.15', '1.2.3.24'))
        self.subnet_manager = db_api.IpamSubnetManager(self.ipam_subnet_id,
                                                       self.neutron_subnet_id)
        self.subnet_manager_id = self.subnet_manager.create(self.ctx)
        self.ctx.session.flush()

    def test_create(self):
        self.assertEqual(self.ipam_subnet_id, self.subnet_manager_id)
        subnet_count = ipam_obj.IpamSubnet.count(
            self.ctx, id=self.ipam_subnet_id)
        self.assertEqual(1, subnet_count)

    def test_remove(self):
        count = db_api.IpamSubnetManager.delete(self.ctx,
                                                self.neutron_subnet_id)
        self.assertEqual(1, count)
        subnet_exists = ipam_obj.IpamSubnet.objects_exist(
            self.ctx, id=self.ipam_subnet_id)
        self.assertFalse(subnet_exists)

    def test_remove_non_existent_subnet(self):
        count = db_api.IpamSubnetManager.delete(self.ctx,
                                                'non-existent')
        self.assertEqual(0, count)

    def _validate_ips(self, pools, db_pool):
        self.assertTrue(
            any(pool == (str(db_pool.first_ip), str(db_pool.last_ip))
                for pool in pools))

    def test_create_pool(self):
        self.subnet_manager.create_pool(self.ctx,
                                        self.single_pool[0],
                                        self.single_pool[1])

        ipam_pools = ipam_obj.IpamAllocationPool.get_objects(
            self.ctx, ipam_subnet_id=self.ipam_subnet_id)
        self._validate_ips([self.single_pool], ipam_pools[0])

    def test_check_unique_allocation(self):
        self.assertTrue(self.subnet_manager.check_unique_allocation(
            self.ctx, self.subnet_ip))

    def test_check_unique_allocation_negative(self):
        self.subnet_manager.create_allocation(self.ctx,
                                              self.subnet_ip)
        self.assertFalse(self.subnet_manager.check_unique_allocation(
            self.ctx, self.subnet_ip))

    def test_list_allocations(self):
        ips = ['1.2.3.4', '1.2.3.6', '1.2.3.7']
        for ip in ips:
            self.subnet_manager.create_allocation(self.ctx, ip)
        allocs = self.subnet_manager.list_allocations(self.ctx)
        self.assertEqual(len(ips), len(allocs))
        for allocation in allocs:
            self.assertIn(str(allocation.ip_address), ips)

    def _test_create_allocation(self):
        self.subnet_manager.create_allocation(self.ctx,
                                              self.subnet_ip)
        alloc = ipam_obj.IpamAllocation.get_objects(
            self.ctx, ipam_subnet_id=self.ipam_subnet_id)
        self.assertEqual(1, len(alloc))
        self.assertEqual(self.subnet_ip, str(alloc[0].ip_address))
        return alloc

    def test_create_allocation(self):
        self._test_create_allocation()

    def test_delete_allocation(self):
        allocs = self._test_create_allocation()
        self.subnet_manager.delete_allocation(self.ctx,
                                              allocs[0].ip_address)

        alloc_exists = ipam_obj.IpamAllocation.objects_exist(
            self.ctx, ipam_subnet_id=self.ipam_subnet_id)
        self.assertFalse(alloc_exists)
