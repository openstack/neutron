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

import collections

from neutron.services.evpn import scheduler
from neutron.tests import base


class TestLeastLoadedChassisScheduler(base.BaseTestCase):

    def _make_scheduler(self, hcg_load):
        return scheduler.LeastLoadedChassisScheduler(hcg_load)

    def test_orders_by_load_ascending(self):
        sched = self._make_scheduler({'hv1': 5, 'hv2': 1, 'hv3': 3})
        result = sched.select(candidates={'hv1', 'hv2', 'hv3'})
        self.assertEqual(['hv2', 'hv3', 'hv1'], result)

    def test_zero_load_first(self):
        sched = self._make_scheduler({'hv1': 2, 'hv2': 0, 'hv3': 1})
        result = sched.select(candidates={'hv1', 'hv2', 'hv3'})
        self.assertEqual('hv2', result[0])

    def test_unknown_chassis_treated_as_zero_load(self):
        sched = self._make_scheduler({'hv1': 3})
        result = sched.select(candidates={'hv1', 'hv_new'})
        self.assertEqual('hv_new', result[0])
        self.assertEqual('hv1', result[1])

    def test_with_existing_chassis(self):
        sched = self._make_scheduler({'hv1': 5, 'hv2': 1, 'hv3': 3})
        result = sched.select(
            candidates={'hv1', 'hv2', 'hv3'},
            existing_chassis=['hv1'])
        self.assertEqual('hv1', result[0])
        self.assertEqual(['hv2', 'hv3'], result[1:])

    def test_with_max_chassis(self):
        sched = self._make_scheduler(
            {'hv1': 5, 'hv2': 1, 'hv3': 3, 'hv4': 0})
        result = sched.select(
            candidates={'hv1', 'hv2', 'hv3', 'hv4'},
            max_chassis=2)
        self.assertEqual(['hv4', 'hv2'], result)

    def test_empty_candidates(self):
        sched = self._make_scheduler({})
        self.assertEqual([], sched.select(candidates=set()))

    def test_max_chassis_caps_existing(self):
        sched = self._make_scheduler({'hv1': 1, 'hv2': 2, 'hv3': 3})
        result = sched.select(
            candidates={'hv1', 'hv2', 'hv3'},
            existing_chassis=['hv2', 'hv3'],
            max_chassis=2)
        # existing_chassis exceeds cap -- result is trimmed to max_chassis
        self.assertEqual(['hv2', 'hv3'], result)

    def test_max_chassis_with_existing_and_new(self):
        sched = self._make_scheduler({'hv1': 5, 'hv2': 1, 'hv3': 3})
        result = sched.select(
            candidates={'hv1', 'hv2', 'hv3'},
            existing_chassis=['hv1'],
            max_chassis=2)
        # hv1 kept first, one new slot filled by least loaded (hv2)
        self.assertEqual(['hv1', 'hv2'], result)


class TestRoundRobinChassisScheduler(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.sched = scheduler.RoundRobinChassisScheduler()

    def test_returns_all_candidates(self):
        result = self.sched.select(candidates={'hv1', 'hv2', 'hv3'})
        self.assertEqual({'hv1', 'hv2', 'hv3'}, set(result))

    def test_empty_candidates(self):
        self.assertEqual([], self.sched.select(candidates=set()))

    def test_single_candidate(self):
        result = self.sched.select(candidates={'hv1'})
        self.assertEqual(['hv1'], result)

    def test_even_distribution_exact_multiple(self):
        """9 routers on 3 chassis => each chassis is primary 3 times."""
        candidates = {'hv1', 'hv2', 'hv3'}
        primaries = collections.Counter()
        for _ in range(9):
            result = self.sched.select(candidates=candidates)
            primaries[result[0]] += 1
        self.assertEqual(3, primaries['hv1'])
        self.assertEqual(3, primaries['hv2'])
        self.assertEqual(3, primaries['hv3'])

    def test_even_distribution_with_remainder(self):
        """10 routers on 3 chassis => 4-3-3 split (no zeros)."""
        candidates = {'hv1', 'hv2', 'hv3'}
        primaries = collections.Counter()
        for _ in range(10):
            result = self.sched.select(candidates=candidates)
            primaries[result[0]] += 1
        self.assertCountEqual([3, 3, 4], primaries.values())

    def test_no_chassis_left_out(self):
        """Every chassis must be primary at least once for N >= K."""
        candidates = {'hv1', 'hv2', 'hv3'}
        primaries = set()
        for _ in range(3):
            result = self.sched.select(candidates=candidates)
            primaries.add(result[0])
        self.assertEqual(candidates, primaries)

    def test_varying_candidate_sets(self):
        """Handles different candidate sets across calls."""
        for _ in range(3):
            self.sched.select(candidates={'hv1', 'hv2', 'hv3'})

        primaries = collections.Counter()
        for _ in range(4):
            result = self.sched.select(candidates={'hv2', 'hv3'})
            primaries[result[0]] += 1
        self.assertEqual(2, primaries['hv2'])
        self.assertEqual(2, primaries['hv3'])

    def test_with_existing_chassis(self):
        """Existing chassis is kept as primary; load is tracked."""
        result = self.sched.select(
            candidates={'hv1', 'hv2', 'hv3'},
            existing_chassis=['hv1'])
        self.assertEqual('hv1', result[0])

        primaries = collections.Counter()
        primaries['hv1'] = 1
        for _ in range(2):
            result = self.sched.select(candidates={'hv1', 'hv2', 'hv3'})
            primaries[result[0]] += 1
        self.assertEqual(1, primaries['hv1'])

    def test_with_max_chassis(self):
        result = self.sched.select(
            candidates={'hv1', 'hv2', 'hv3', 'hv4'},
            max_chassis=2)
        self.assertEqual(2, len(result))
