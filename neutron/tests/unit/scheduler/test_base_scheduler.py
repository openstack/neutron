# Copyright 2020 Red Hat Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from unittest import mock

from neutron.scheduler import base_scheduler

from neutron.tests import base


class GetVacantBindingFilterCase(base.BaseTestCase):

    def test_get_vacant_binding_index_no_agents(self):
        ret = base_scheduler.get_vacant_binding_index(0, [], 1)
        self.assertEqual(-1, ret)

    def test_get_vacant_binding_index_several_agents(self):
        ret = base_scheduler.get_vacant_binding_index(1, [], 1)
        self.assertEqual(1, ret)

        ret = base_scheduler.get_vacant_binding_index(
            1, [mock.Mock(binding_index=1)], 1)
        self.assertEqual(-1, ret)

        ret = base_scheduler.get_vacant_binding_index(
            3, [mock.Mock(binding_index=1), mock.Mock(binding_index=3)], 1)
        self.assertEqual(2, ret)

        # Binding list starting in 2, two elements, required three.
        ret = base_scheduler.get_vacant_binding_index(
            3, [mock.Mock(binding_index=2), mock.Mock(binding_index=3)], 1)
        self.assertEqual(1, ret)

        # Binding list starting in 2, two elements, required two.
        ret = base_scheduler.get_vacant_binding_index(
            2, [mock.Mock(binding_index=2), mock.Mock(binding_index=3)], 1)
        self.assertEqual(-1, ret)

        # Binding list starting in 2, two elements, required one.
        ret = base_scheduler.get_vacant_binding_index(
            1, [mock.Mock(binding_index=2), mock.Mock(binding_index=3)], 1)
        self.assertEqual(-1, ret)

    def test_get_vacant_binding_index_force_scheduling(self):
        ret = base_scheduler.get_vacant_binding_index(
            3, [mock.Mock(binding_index=1), mock.Mock(binding_index=2),
                mock.Mock(binding_index=3), mock.Mock(binding_index=5),
                mock.Mock(binding_index=7)], 1, force_scheduling=True)
        self.assertEqual(4, ret)

        ret = base_scheduler.get_vacant_binding_index(
            3, [mock.Mock(binding_index=1), mock.Mock(binding_index=2),
                mock.Mock(binding_index=3), mock.Mock(binding_index=4),
                mock.Mock(binding_index=5)], 1, force_scheduling=True)
        self.assertEqual(6, ret)

        ret = base_scheduler.get_vacant_binding_index(
            3, [mock.Mock(binding_index=2), mock.Mock(binding_index=3),
                mock.Mock(binding_index=4), mock.Mock(binding_index=5),
                mock.Mock(binding_index=6)], 1, force_scheduling=True)
        self.assertEqual(1, ret)
