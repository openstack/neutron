# Copyright 2025 Red Hat Inc.
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

from neutron_lib import constants
from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron_lib.objects import exceptions as o_exc
from oslo_config import cfg

from neutron.conf import common as common_config
from neutron.conf.plugins.ml2 import config as ml2_config
from neutron.conf.plugins.ml2.drivers import driver_type as driver_type_config
from neutron.objects import network_segment_range as range_obj
from neutron.plugins.ml2.drivers import type_vlan
from neutron.tests.unit import testlib_api


def _initialize_network_segment_range_support(type_driver, start_time):
    # This method is similar to
    # ``VlanTypeDriverBase.initialize_network_segment_range_support``.
    # The method first deletes the existing default network ranges and then
    # creates the new ones. It also adds an extra second before closing the
    # DB transaction.
    admin_context = context.get_admin_context()
    try:
        with db_api.CONTEXT_WRITER.using(admin_context):
            type_driver._delete_expired_default_network_segment_ranges(
                admin_context, start_time)
            type_driver._populate_new_default_network_segment_ranges(
                admin_context, start_time)
    except o_exc.NeutronDbObjectDuplicateEntry:
        pass


class VlanTypeDriverBaseTestCase(testlib_api.MySQLTestCaseMixin,
                                   testlib_api.SqlTestCase):
    def setUp(self):
        super().setUp()
        cfg.CONF.register_opts(common_config.core_opts)
        ml2_config.register_ml2_plugin_opts()
        driver_type_config.register_ml2_drivers_vlan_opts()
        ml2_config.cfg.CONF.set_override(
            'service_plugins', 'network_segment_range')
        self.min = 1001
        self.max = 1020
        self.net_type = constants.TYPE_VLAN
        self.ranges = [f'phys1:{self.min}:{self.max}',
                       f'phys2:{self.min}:{self.max}',
                       f'phys3:{self.min}:{self.max}',
                       ]
        ml2_config.cfg.CONF.set_override(
            'network_vlan_ranges', self.ranges, group='ml2_type_vlan')
        self.admin_ctx = context.get_admin_context()
        self.type_driver = type_vlan.VlanTypeDriver()
        self.type_driver.initialize()

    def _check_sranges(self, sranges):
        self.assertEqual(len(self.ranges), len(sranges))
        for _srange in sranges:
            self.assertEqual(self.net_type, _srange.network_type)
            self.assertEqual(self.min, _srange.minimum)
            self.assertEqual(self.max, _srange.maximum)
            self.assertIn(_srange.physical_network,
                          ('phys1', 'phys2', 'phys3'))

        self.assertEqual({'phys1': [(self.min, self.max)],
                          'phys2': [(self.min, self.max)],
                          'phys3': [(self.min, self.max)]},
                         self.type_driver._network_vlan_ranges)

    def test_initialize_network_segment_range_support(self):
        # Execute the initialization several times with different start times.
        for start_time in range(3):
            self.type_driver.initialize_network_segment_range_support(
                start_time)
            sranges = range_obj.NetworkSegmentRange.get_objects(self.admin_ctx)
            self._check_sranges(sranges)

    def _test_initialize_nsrange(self, same_init_time=True):
        max_workers = 3
        _futures = []
        with futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            if same_init_time:
                # All workers are started at the same init time.
                _futures.append(executor.submit(
                    _initialize_network_segment_range_support,
                    self.type_driver, 0))
            else:
                # All workers have different init times.
                for idx in range(max_workers):
                    _futures.append(executor.submit(
                        _initialize_network_segment_range_support,
                        self.type_driver, idx))
            for _future in _futures:
                _future.result()

        sranges = range_obj.NetworkSegmentRange.get_objects(self.admin_ctx)
        self._check_sranges(sranges)

    def test__initialize_nsrange_support_parallel_exec_same_init_time(self):
        self._test_initialize_nsrange(same_init_time=True)

    def test_initialize_nsrange_support_parallel_exec_diff_init_time(self):
        self._test_initialize_nsrange(same_init_time=False)
