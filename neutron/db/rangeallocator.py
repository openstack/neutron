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

import random as _random

from oslo_utils import uuidutils
import sqlalchemy as sa


class RangeAllocator:
    """Allocator for a scoped integer column in a HasId-style table.

    Atomically claims the smallest unoccupied integer in [min_val, max_val]
    within a scope (e.g. physnet for VNIs).

    The target table must follow Neutron's HasId convention:

      - A UUID 'id' primary key (String(36), default=uuidutils.generate_uuid)
      - An integer value column
      - A scope column
      - A UNIQUE constraint on (value_col, scope_col)

    Because the UUID is generated in Python and included in the INSERT,
    no RETURNING clause or lastrowid is required.  The statement works
    identically on all supported databases (SQLite, PostgreSQL, MySQL,
    MariaDB).

    The INSERT...SELECT is atomic under the UNIQUE constraint.  Concurrent
    transactions that land on the same value race on the INSERT; the loser
    gets a DBDuplicateEntry which propagates to the caller.  Apply
    @db_api.retry_if_session_inactive() above @db_api.CONTEXT_WRITER so
    that each retry opens a fresh transaction with a new UUID.

    SQL statements are built once at construction time.

    Subclasses may override _gap_source() to change the allocation strategy,
    and _make_params() to supply any additional bind parameters required by
    their _gap_source() implementation.
    """

    def __init__(self, table, value_col_name, scope_col_name,
                 scope_param_type, exception_class):
        """:param table: SQLAlchemy Table object (reqs HasId-style UUID id)
        :param value_col_name: name of the integer column to allocate from
        :param scope_col_name: name of the column that scopes uniqueness
        :param scope_param_type: SQLAlchemy type for the scope bind parameter
        :param exception_class: raised when no value is available; must
                                accept (min_val, max_val) positional arguments
        """
        self._table = table
        self._value_col_name = value_col_name
        self._scope_col_name = scope_col_name
        self._exception_class = exception_class

        self._value_col = table.c[value_col_name]
        self._scope_col = table.c[scope_col_name]
        self._min_val = sa.bindparam('min_val', type_=sa.Integer)
        self._max_val = sa.bindparam('max_val', type_=sa.Integer)
        self._scope_p = sa.bindparam('scope_val', type_=scope_param_type)
        self._id_p = sa.bindparam('allocation_id', type_=sa.String(36))

        source = self._gap_source()
        self._stmt = (
            table.insert()
            .from_select(
                ['id', value_col_name, scope_col_name],
                sa.select(self._id_p, source.c.next_val, self._scope_p)
                  .where(source.c.next_val.isnot(None))
            )
        )

    def _gap_source(self):
        """Subquery returning the next_val to allocate.

        Returns a subquery with a single next_val column containing the
        integer to claim, or NULL if none is available.  The default
        implementation claims the smallest unoccupied value in the range.
        Subclasses override this to change the allocation strategy.
        """
        range_start = sa.select(self._min_val.label('candidate'))

        after_existing = sa.select(
            (self._value_col + 1).label('candidate')
        ).where(
            sa.and_(self._value_col >= self._min_val,
                    self._value_col < self._max_val,
                    self._scope_col == self._scope_p)
        )

        candidates = sa.union_all(range_start, after_existing).subquery()

        return sa.select(
            sa.func.min(candidates.c.candidate).label('next_val')
        ).where(
            sa.and_(
                candidates.c.candidate <= self._max_val,
                candidates.c.candidate.notin_(
                    sa.select(self._value_col)
                    .where(self._scope_col == self._scope_p)
                )
            )
        ).subquery()

    @staticmethod
    def _make_params(min_val, max_val, scope_val, allocation_id):
        """Return the bind parameter dict for execute().

        Subclasses that introduce additional bind parameters in _gap_source()
        should override this to include them.
        """
        return {
            'min_val': min_val,
            'max_val': max_val,
            'scope_val': scope_val,
            'allocation_id': allocation_id,
        }

    def allocate(self, context, min_val, max_val, scope_val):
        """Claim the next available value in [min_val, max_val] for scope_val.

        Returns (allocation_id, allocated_value) where allocation_id is a
        Python-generated UUID suitable for use as a foreign key.

        Raises self._exception_class(min_val, max_val) if no value is
        available.  Lets DBDuplicateEntry propagate for retry handling by
        the caller.
        """
        allocation_id = uuidutils.generate_uuid()
        params = self._make_params(min_val, max_val, scope_val, allocation_id)

        context.session.execute(self._stmt, params)

        row = context.session.execute(
            sa.select(self._table.c[self._value_col_name])
            .where(self._table.c.id == allocation_id)
        ).fetchone()

        if row is None:
            raise self._exception_class(min_val, max_val)

        return allocation_id, getattr(row, self._value_col_name)


class RandomRangeAllocator(RangeAllocator):
    """RangeAllocator that claims a randomly chosen unoccupied value.

    Scans taken values, computes gaps, and maps a Python-generated random
    proportion to a position in the free set.  Guaranteed to find a free
    value if one exists.  O(K) in taken values.

    rand_val is provided as a Python-generated float rather than using
    SQL random() to avoid CTE re-evaluation issues on non-materialized
    CTEs, which could produce different values in the SELECT column and
    WHERE clause and return incorrect results.
    """

    def _gap_source(self):
        """Subquery returning a randomly selected unoccupied value."""
        rand_val = sa.bindparam('rand_val', type_=sa.Float)

        taken = sa.select(
            self._value_col.label('val'),
            sa.func.coalesce(
                sa.func.lag(self._value_col).over(order_by=self._value_col),
                self._min_val - 1,
            ).label('prev_val'),
        ).where(
            sa.and_(
                self._scope_col == self._scope_p,
                self._value_col >= self._min_val,
                self._value_col <= self._max_val,
            )
        ).cte('taken')

        inner_gaps = sa.select(
            (taken.c.prev_val + 1).label('gap_start'),
            (taken.c.val - taken.c.prev_val - 1).label('gap_size'),
        ).where(taken.c.val - taken.c.prev_val > 1)

        max_allocated = (
            sa.select(sa.func.max(self._value_col).label('val'))
            .where(
                sa.and_(
                    self._scope_col == self._scope_p,
                    self._value_col >= self._min_val,
                    self._value_col <= self._max_val,
                )
            )
            .cte('max_allocated')
        )
        trailing_gap = (
            sa.select(
                sa.func.coalesce(
                    max_allocated.c.val + 1, self._min_val).label('gap_start'),
                (self._max_val - sa.func.coalesce(
                    max_allocated.c.val, self._min_val - 1)).label('gap_size'),
            )
            .select_from(max_allocated)
        )

        gaps = sa.union_all(inner_gaps, trailing_gap).cte('gaps')

        free_count = sa.select(
            sa.func.sum(gaps.c.gap_size).label('n')
        ).cte('free_count')

        n = free_count.c.n
        target = sa.select(
            sa.cast(sa.func.floor(rand_val * n), sa.Integer).label('idx')
        ).where(n > 0).cte('target')

        cumul = sa.select(
            gaps.c.gap_start,
            gaps.c.gap_size,
            (sa.func.sum(gaps.c.gap_size).over(order_by=gaps.c.gap_start) -
             gaps.c.gap_size).label('cum_before'),
        ).cte('cumul')

        idx = sa.select(target.c.idx).scalar_subquery()
        return (
            sa.select(
                (cumul.c.gap_start + idx -
                 cumul.c.cum_before).label('next_val')
            )
            .where(idx.between(cumul.c.cum_before,
                               cumul.c.cum_before + cumul.c.gap_size - 1))
            .limit(1)
            .subquery()
        )

    @staticmethod
    def _make_params(min_val, max_val, scope_val, allocation_id):
        params = super()._make_params(
            min_val, max_val, scope_val, allocation_id)
        params['rand_val'] = _random.random()  # noqa: S311
        return params
