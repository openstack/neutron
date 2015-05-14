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

from oslo_utils import uuidutils

from neutron import context
from neutron.ipam.drivers.neutrondb_ipam import db_api
from neutron.ipam.drivers.neutrondb_ipam import db_models
from neutron.tests.unit import testlib_api


class TestIpamSubnetManager(testlib_api.SqlTestCase):
    """Test case for SubnetManager DB helper class"""

    def setUp(self):
        super(TestIpamSubnetManager, self).setUp()
        self.ctx = context.get_admin_context()
        self.neutron_subnet_id = uuidutils.generate_uuid()
        self.ipam_subnet_id = uuidutils.generate_uuid()
        self.subnet_ip = '1.2.3.4'
        self.single_pool = ('1.2.3.4', '1.2.3.10')
        self.multi_pool = (('1.2.3.2', '1.2.3.12'), ('1.2.3.15', '1.2.3.24'))
        self.subnet_manager = db_api.IpamSubnetManager(self.ipam_subnet_id,
                                                       self.neutron_subnet_id)
        self.subnet_manager_id = self.subnet_manager.create(self.ctx.session)
        self.ctx.session.flush()

    def test_create(self):
        self.assertEqual(self.ipam_subnet_id, self.subnet_manager_id)
        subnets = self.ctx.session.query(db_models.IpamSubnet).filter_by(
            id=self.ipam_subnet_id).all()
        self.assertEqual(1, len(subnets))

    def test_remove(self):
        count = db_api.IpamSubnetManager.delete(self.ctx.session,
                                                self.neutron_subnet_id)
        self.assertEqual(1, count)
        subnets = self.ctx.session.query(db_models.IpamSubnet).filter_by(
            id=self.ipam_subnet_id).all()
        self.assertEqual(0, len(subnets))

    def test_remove_non_existent_subnet(self):
        count = db_api.IpamSubnetManager.delete(self.ctx.session,
                                                'non-existent')
        self.assertEqual(0, count)

    def _create_pools(self, pools):
        db_pools = []
        for pool in pools:
            db_pool = self.subnet_manager.create_pool(self.ctx.session,
                                                      pool[0],
                                                      pool[1])
            db_pools.append(db_pool)
        return db_pools

    def _validate_ips(self, pool, db_pool):
        self.assertEqual(pool[0], db_pool.first_ip)
        self.assertEqual(pool[1], db_pool.last_ip)

    def test_create_pool(self):
        db_pools = self._create_pools([self.single_pool])

        ipam_pool = self.ctx.session.query(db_models.IpamAllocationPool).\
            filter_by(ipam_subnet_id=self.ipam_subnet_id).first()
        self._validate_ips(self.single_pool, ipam_pool)

        range = self.ctx.session.query(db_models.IpamAvailabilityRange).\
            filter_by(allocation_pool_id=db_pools[0].id).first()
        self._validate_ips(self.single_pool, range)

    def _test_get_first_range(self, locking):
        self._create_pools(self.multi_pool)
        range = self.subnet_manager.get_first_range(self.ctx.session,
                                                    locking=locking)
        self._validate_ips(self.multi_pool[0], range)

    def test_get_first_range(self):
        self._test_get_first_range(False)

    def test_get_first_range_locking(self):
        self._test_get_first_range(True)

    def test_list_ranges_by_subnet_id(self):
        self._create_pools(self.multi_pool)

        db_ranges = self.subnet_manager.list_ranges_by_subnet_id(
            self.ctx.session,
            self.ipam_subnet_id).all()
        self.assertEqual(2, len(db_ranges))
        self.assertEqual(db_models.IpamAvailabilityRange, type(db_ranges[0]))

    def test_list_ranges_by_allocation_pool(self):
        db_pools = self._create_pools([self.single_pool])
        # generate ids for allocation pools on flush
        self.ctx.session.flush()
        db_ranges = self.subnet_manager.list_ranges_by_allocation_pool(
            self.ctx.session,
            db_pools[0].id).all()
        self.assertEqual(1, len(db_ranges))
        self.assertEqual(db_models.IpamAvailabilityRange, type(db_ranges[0]))
        self._validate_ips(self.single_pool, db_ranges[0])

    def test_create_range(self):
        self._create_pools([self.single_pool])
        pool = self.ctx.session.query(db_models.IpamAllocationPool).\
            filter_by(ipam_subnet_id=self.ipam_subnet_id).first()
        self._validate_ips(self.single_pool, pool)
        allocation_pool_id = pool.id

        # delete the range
        db_range = self.subnet_manager.list_ranges_by_allocation_pool(
            self.ctx.session,
            pool.id).first()
        self._validate_ips(self.single_pool, db_range)
        self.ctx.session.delete(db_range)

        # create a new range
        range_start = '1.2.3.5'
        range_end = '1.2.3.9'
        new_range = self.subnet_manager.create_range(self.ctx.session,
                                                     allocation_pool_id,
                                                     range_start,
                                                     range_end)
        self.assertEqual(range_start, new_range.first_ip)
        self.assertEqual(range_end, new_range.last_ip)

    def test_check_unique_allocation(self):
        self.assertTrue(self.subnet_manager.check_unique_allocation(
            self.ctx.session, self.subnet_ip))

    def test_check_unique_allocation_negative(self):
        self.subnet_manager.create_allocation(self.ctx.session,
                                              self.subnet_ip)
        self.assertFalse(self.subnet_manager.check_unique_allocation(
            self.ctx.session, self.subnet_ip))

    def test_list_allocations(self):
        ips = ['1.2.3.4', '1.2.3.6', '1.2.3.7']
        for ip in ips:
            self.subnet_manager.create_allocation(self.ctx.session, ip)
        allocs = self.subnet_manager.list_allocations(self.ctx.session).all()
        self.assertEqual(len(ips), len(allocs))
        for allocation in allocs:
            self.assertIn(allocation.ip_address, ips)

    def _test_create_allocation(self):
        self.subnet_manager.create_allocation(self.ctx.session,
                                              self.subnet_ip)
        alloc = self.ctx.session.query(db_models.IpamAllocation).filter_by(
            ipam_subnet_id=self.ipam_subnet_id).all()
        self.assertEqual(1, len(alloc))
        self.assertEqual(self.subnet_ip, alloc[0].ip_address)
        return alloc

    def test_create_allocation(self):
        self._test_create_allocation()

    def test_delete_allocation(self):
        allocs = self._test_create_allocation()
        self.subnet_manager.delete_allocation(self.ctx.session,
                                              allocs[0].ip_address)

        allocs = self.ctx.session.query(db_models.IpamAllocation).filter_by(
            ipam_subnet_id=self.ipam_subnet_id).all()
        self.assertEqual(0, len(allocs))
