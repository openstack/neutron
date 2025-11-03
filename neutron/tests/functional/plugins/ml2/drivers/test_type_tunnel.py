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
import time

from neutron_lib import constants
from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron_lib.objects import exceptions as o_exc
from oslo_config import cfg

from neutron.conf import common as common_config
from neutron.conf.plugins.ml2 import config as ml2_config
from neutron.conf.plugins.ml2.drivers import driver_type as driver_type_config
from neutron.objects import network_segment_range as range_obj
from neutron.plugins.ml2.drivers import type_geneve
from neutron.tests.unit import testlib_api


def _initialize_network_segment_range_support(type_driver, worker_num,
                                              same_init_time):
    # This method is similar to
    # ``_TunnelTypeDriverBase.initialize_network_segment_range_support``.
    # The method first deletes the existing default network ranges and then
    # creates the new ones. It also adds an extra second before closing the
    # DB transaction.
    #
    start_time = worker_num if not same_init_time else 0
    admin_context = context.get_admin_context()
    try:
        time.sleep(worker_num / 4)
        with db_api.CONTEXT_WRITER.using(admin_context):
            type_driver._delete_expired_default_network_segment_ranges(
                admin_context, start_time)
            type_driver._populate_new_default_network_segment_ranges(
                admin_context, start_time)
    except o_exc.NeutronDbObjectDuplicateEntry:
        pass


class TunnelTypeDriverBaseTestCase(testlib_api.MySQLTestCaseMixin,
                                   testlib_api.SqlTestCase):
    def setUp(self):
        super().setUp()
        cfg.CONF.register_opts(common_config.core_opts)
        ml2_config.register_ml2_plugin_opts()
        driver_type_config.register_ml2_drivers_geneve_opts()
        ml2_config.cfg.CONF.set_override(
            'service_plugins', 'network_segment_range')
        self.min = 1001
        self.max = 1020
        self.net_type = constants.TYPE_GENEVE
        ml2_config.cfg.CONF.set_override(
            'vni_ranges', f'{self.min}:{self.max}', group='ml2_type_geneve')
        self.admin_ctx = context.get_admin_context()
        self.type_driver = type_geneve.GeneveTypeDriver()
        self.type_driver.initialize()

    def _check_sranges(self, sranges):
        self.assertEqual(1, len(sranges))
        self.assertEqual(self.net_type, sranges[0].network_type)
        self.assertEqual(self.min, sranges[0].minimum)
        self.assertEqual(self.max, sranges[0].maximum)
        self.assertEqual([(self.min, self.max)],
                         self.type_driver._tunnel_ranges)

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
            for idx in range(max_workers):
                _futures.append(executor.submit(
                    _initialize_network_segment_range_support,
                    self.type_driver, idx, same_init_time))
            for _future in _futures:
                _future.result()

        sranges = range_obj.NetworkSegmentRange.get_objects(self.admin_ctx)
        self._check_sranges(sranges)

    def test_initialize_nsrange_support_parallel_exec_same_init_time(self):
        self._test_initialize_nsrange(same_init_time=True)

    def test_initialize_nsrange_support_parallel_exec_diff_init_time(self):
        self._test_initialize_nsrange(same_init_time=False)
