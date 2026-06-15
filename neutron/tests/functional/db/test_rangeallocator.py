# Copyright 2026 Red Hat, LLC
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

from concurrent import futures

from neutron_lib import context
from neutron_lib.db import api as db_api
import sqlalchemy as sa

from neutron.db.models import vxlan_vlan_allocations as alloc_models
from neutron.db import rangeallocator
from neutron.services.evpn import exceptions as evpn_exc
from neutron.tests.unit import testlib_api

# required for testresources to optimise same-backend tests together
load_tests = testlib_api.module_load_tests

_PHYSNET = 'test-physnet'
_OTHER_PHYSNET = 'other-physnet'


class TestRangeAllocatorBase(testlib_api.SqlTestCase):
    """Tests for RangeAllocator against a real SQL engine.

    Runs against SQLite by default (RETURNING path).
    TestRangeAllocatorMySQL runs the same suite against MySQL
    (LAST_INSERT_ID path).
    """

    def setUp(self):
        super().setUp()
        self.ctx = context.Context(
            user_id=None, project_id=None, is_admin=True, overwrite=False)
        self.table = alloc_models.VNIAllocation.__table__

    def _allocate(self, min_vni=1, max_vni=100, physnet=_PHYSNET):
        with db_api.CONTEXT_WRITER.using(self.ctx):
            return self.allocator.allocate(
                self.ctx, min_vni, max_vni, physnet)

    def _insert(self, vni, physnet=_PHYSNET):
        """Directly insert a VNI to set up a specific allocation state."""
        with db_api.CONTEXT_WRITER.using(self.ctx):
            result = self.ctx.session.execute(
                self.table.insert().values(vni=vni, physnet=physnet))
            return result.inserted_primary_key[0]

    def _delete(self, allocation_id):
        with db_api.CONTEXT_WRITER.using(self.ctx):
            self.ctx.session.execute(
                self.table.delete().where(self.table.c.id == allocation_id))

    def _all_vnis(self, physnet=_PHYSNET):
        with db_api.CONTEXT_READER.using(self.ctx):
            rows = self.ctx.session.execute(
                sa.select(self.table.c.vni)
                .where(self.table.c.physnet == physnet)
                .order_by(self.table.c.vni)
            ).fetchall()
        return [r.vni for r in rows]


class TestRangeAllocator(TestRangeAllocatorBase):
    def setUp(self):
        super().setUp()
        self.allocator = rangeallocator.RangeAllocator(
            table=self.table,
            value_col_name='vni',
            scope_col_name='physnet',
            scope_param_type=sa.String,
            exception_class=evpn_exc.EVPNNoVniAvailable,
        )

    def test_allocate_from_empty_gets_min(self):
        alloc_id, vni = self._allocate(min_vni=10, max_vni=100)
        self.assertEqual(10, vni)
        self.assertIsNotNone(alloc_id)

    def test_allocate_sequential_fills_in_order(self):
        _, vni1 = self._allocate(min_vni=1, max_vni=5)
        _, vni2 = self._allocate(min_vni=1, max_vni=5)
        _, vni3 = self._allocate(min_vni=1, max_vni=5)
        self.assertEqual([1, 2, 3], sorted([vni1, vni2, vni3]))

    def test_allocate_fills_freed_gap(self):
        alloc_id1, vni1 = self._allocate(min_vni=1, max_vni=5)
        _, vni2 = self._allocate(min_vni=1, max_vni=5)
        _, vni3 = self._allocate(min_vni=1, max_vni=5)
        self.assertEqual(1, vni1)
        self.assertEqual(2, vni2)
        self.assertEqual(3, vni3)

        self._delete(alloc_id1)
        _, reused = self._allocate(min_vni=1, max_vni=5)
        self.assertEqual(1, reused)

    def test_allocate_skips_existing(self):
        # Pre-populate with a gap: 1, 3 — allocator should return 2
        self._insert(1)
        self._insert(3)
        _, vni = self._allocate(min_vni=1, max_vni=5)
        self.assertEqual(2, vni)

    def test_allocate_above_contiguous_block(self):
        self._insert(1)
        self._insert(2)
        self._insert(3)
        _, vni = self._allocate(min_vni=1, max_vni=5)
        self.assertEqual(4, vni)

    def test_allocate_range_exhausted_raises(self):
        self._insert(1)
        self._insert(2)
        self._insert(3)
        self.assertRaises(
            evpn_exc.EVPNNoVniAvailable,
            self._allocate, min_vni=1, max_vni=3)

    def test_allocate_scope_isolated(self):
        # Filling _PHYSNET should not affect _OTHER_PHYSNET allocation
        self._insert(1, physnet=_PHYSNET)
        self._insert(2, physnet=_PHYSNET)

        _, vni = self._allocate(min_vni=1, max_vni=5, physnet=_OTHER_PHYSNET)
        self.assertEqual(1, vni)

    def test_allocate_scope_does_not_cross_contaminate(self):
        # Allocating in one scope leaves the other untouched
        self._allocate(min_vni=1, max_vni=5, physnet=_PHYSNET)
        self._allocate(min_vni=1, max_vni=5, physnet=_OTHER_PHYSNET)

        self.assertEqual([1], self._all_vnis(_PHYSNET))
        self.assertEqual([1], self._all_vnis(_OTHER_PHYSNET))

    def test_allocation_id_is_usable_as_foreign_key(self):
        # allocation_id must be a valid surrogate PK for use in
        # evpn_l3_instances.allocation_id
        alloc_id, vni = self._allocate()
        self.assertIsNotNone(alloc_id)
        with db_api.CONTEXT_READER.using(self.ctx):
            row = self.ctx.session.execute(
                sa.select(self.table).where(self.table.c.id == alloc_id)
            ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(vni, row.vni)

    def test_custom_allocator_generic(self):
        """RangeAllocator works with any table matching the contract."""
        # Build a minimal in-memory table to confirm the allocator is
        # not tied to VXLANVNIAllocation specifically.
        meta = sa.MetaData()
        test_table = sa.Table(
            'test_alloc_generic', meta,
            sa.Column('id', sa.String(36), primary_key=True),
            sa.Column('val', sa.Integer, nullable=False),
            sa.Column('scope', sa.String(64), nullable=False),
            sa.UniqueConstraint('val', 'scope'),
        )
        with db_api.CONTEXT_WRITER.using(self.ctx):
            test_table.create(self.ctx.session.get_bind())

        alloc = rangeallocator.RangeAllocator(
            table=test_table,
            value_col_name='val',
            scope_col_name='scope',
            scope_param_type=sa.String,
            exception_class=evpn_exc.EVPNNoVniAvailable,
        )

        with db_api.CONTEXT_WRITER.using(self.ctx):
            alloc_id, val = alloc.allocate(self.ctx, 5, 10, 'myscope')
        self.assertEqual(5, val)
        self.assertIsNotNone(alloc_id)


class TestAllocatorMySQL(testlib_api.MySQLTestCaseMixin):
    def setUp(self):
        super().setUp()
        with db_api.CONTEXT_WRITER.using(self.ctx):
            dialect = self.ctx.session.get_bind().dialect.name
        self.assertIn(dialect, ('mysql', 'mariadb'),
                      "expected MySQL/MariaDB but got: %s" % dialect)

    def test_engine_is_mysql(self):
        # @@version_comment is a MySQL/MariaDB system variable that does
        # not exist in SQLite.  If this query succeeds the test is
        # genuinely running against MySQL/MariaDB.
        with db_api.CONTEXT_READER.using(self.ctx):
            row = self.ctx.session.execute(
                sa.text('SELECT @@version_comment')).fetchone()
        self.assertIsNotNone(row)


class TestRangeAllocatorMySQL(TestAllocatorMySQL, TestRangeAllocator):
    """Re-runs the full suite against MySQL (LAST_INSERT_ID path).

    Skipped automatically if MySQL is unavailable.
    """

    def test_allocate_concurrent_no_duplicates(self):
        """Two threads allocating simultaneously must get distinct VNIs.

        Exercises the UNIQUE constraint race under real concurrent writes.
        SQLite serialises writes so this test only runs against MySQL where
        true concurrency and deadlocks can occur.  retry_db_errors handles
        DBDeadlock and DBDuplicateEntry transparently.
        """
        results = []

        @db_api.retry_db_errors
        def allocate():
            ctx = context.Context(
                user_id=None, project_id=None,
                is_admin=True, overwrite=False)
            with db_api.CONTEXT_WRITER.using(ctx):
                alloc_id, vni = self.allocator.allocate(
                    ctx, 1, 10, _PHYSNET)
            results.append(vni)

        with futures.ThreadPoolExecutor(max_workers=2) as pool:
            futs = [pool.submit(allocate), pool.submit(allocate)]
            for f in futures.as_completed(futs):
                f.result()

        self.assertEqual(2, len(results))
        self.assertEqual(2, len(set(results)), "concurrent allocations must "
                         "produce distinct VNIs, got %s" % results)


class TestRandomRangeAllocator(TestRangeAllocatorBase):
    """Tests for RangeAllocator with strategy=RANDOM.

    Runs against SQLite by default.
    TestRandomRangeAllocatorMySQL runs the same suite against MySQL.
    """

    def setUp(self):
        super().setUp()
        self.allocator = rangeallocator.RandomRangeAllocator(
            table=self.table,
            value_col_name='vni',
            scope_col_name='physnet',
            scope_param_type=sa.String,
            exception_class=evpn_exc.EVPNNoVniAvailable,
        )

    def test_random_result_within_range(self):
        _, vni = self._allocate(min_vni=5, max_vni=10)
        self.assertGreaterEqual(vni, 5)
        self.assertLessEqual(vni, 10)

    def test_random_multiple_allocations_distinct(self):
        _, vni1 = self._allocate(min_vni=1, max_vni=5)
        _, vni2 = self._allocate(min_vni=1, max_vni=5)
        _, vni3 = self._allocate(min_vni=1, max_vni=5)
        self.assertEqual(3, len({vni1, vni2, vni3}))

    def test_random_finds_last_available(self):
        """Gap scan must find the sole remaining value in one query."""
        for vni in [1, 2, 4, 5]:
            self._insert(vni)
        _, vni = self._allocate(min_vni=1, max_vni=5)
        self.assertEqual(3, vni)

    def test_random_range_exhausted_raises(self):
        for vni in [1, 2, 3]:
            self._insert(vni)
        self.assertRaises(
            evpn_exc.EVPNNoVniAvailable,
            self._allocate, min_vni=1, max_vni=3)

    def test_random_scope_isolated(self):
        for vni in range(1, 5):
            self._insert(vni, physnet=_PHYSNET)
        _, vni = self._allocate(min_vni=1, max_vni=5, physnet=_OTHER_PHYSNET)
        self.assertGreaterEqual(vni, 1)
        self.assertLessEqual(vni, 5)

    def test_random_allocation_id_usable_as_fk(self):
        alloc_id, vni = self._allocate()
        self.assertIsNotNone(alloc_id)
        with db_api.CONTEXT_READER.using(self.ctx):
            row = self.ctx.session.execute(
                sa.select(self.table).where(self.table.c.id == alloc_id)
            ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(vni, row.vni)

    def test_random_all_values_allocatable(self):
        """Gap scan guarantees every value reachable regardless of density."""
        allocated = set()
        for _ in range(20):
            _, vni = self._allocate(min_vni=1, max_vni=20)
            allocated.add(vni)
        self.assertEqual(set(range(1, 21)), allocated)


class TestRandomRangeAllocatorMySQL(TestAllocatorMySQL,
                                    TestRandomRangeAllocator):
    """Re-runs random strategy suite against MySQL.

    Skipped automatically if MySQL is unavailable.
    """
