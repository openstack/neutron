# Copyright 2019 Red Hat, Inc.
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
import threading
from unittest import mock

from oslo_config import cfg
from oslo_service import loopingcall

from neutron.plugins.ml2.drivers.ovn.mech_driver import mech_driver
from neutron.tests import base
from neutron.tests.functional import base as functional_base


NEW_CONFIG_GROUP = cfg.OptGroup('testgroup',
                                title='Test wrapping cfg register')
SOME_OPTIONS = [
    cfg.StrOpt('str_opt', default='default_value'),
    cfg.StrOpt('int_opt', default=1),
    cfg.BoolOpt('bool_opt', default=True)
]


def register_some_options(cfg=cfg.CONF):
    cfg.register_opts(SOME_OPTIONS, 'testgroup')


class ConfigDecoratorTestCase(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        cfg.CONF.register_group(NEW_CONFIG_GROUP)

    def test_no_config_decorator(self):
        register_some_options()
        self.assertEqual('default_value', cfg.CONF.testgroup.str_opt)
        self.assertEqual('1', cfg.CONF.testgroup.int_opt)
        self.assertTrue(cfg.CONF.testgroup.bool_opt)

    def test_override_variables(self):
        opts = [('str_opt', 'another_value', 'testgroup'),
                ('int_opt', 123, 'testgroup'),
                ('bool_opt', False, 'testgroup')]
        cfg_decorator = functional_base.config_decorator(register_some_options,
                                                         opts)
        mock.patch('neutron.tests.unit.tests.functional.test_base.'
                   'register_some_options', new=cfg_decorator).start()
        register_some_options()
        self.assertEqual('another_value', cfg.CONF.testgroup.str_opt)
        self.assertEqual('123', cfg.CONF.testgroup.int_opt)
        self.assertFalse(cfg.CONF.testgroup.bool_opt)


class OVNHeartbeatCleanupTestCase(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.functional_test = functional_base.TestOVNFunctionalBase()
        self.functional_test.maintenance_worker = True
        self.driver = mech_driver.OVNMechanismDriver()
        self.driver._heartbeat = None
        self.driver._post_fork_event = threading.Event()
        self.driver._post_fork_event.set()
        self.driver.nb_ovn = mock.Mock()
        self.driver.sb_ovn = mock.Mock()
        self.driver.nb_synchronizer = mock.Mock()
        self.driver.sb_synchronizer = mock.Mock()
        self.functional_test.mech_driver = self.driver
        for api in (self.driver.nb_ovn, self.driver.sb_ovn):
            api.idl.notify_handler.notify_thread.is_alive.return_value = False

    def _start_heartbeat(self, callback, initial_delay=None):
        heartbeat = self.driver._heartbeat = (
            loopingcall.FixedIntervalLoopingCall(callback))
        heartbeat.start(interval=60, initial_delay=initial_delay)
        self.addCleanup(heartbeat.wait)
        self.addCleanup(heartbeat.stop)
        return heartbeat

    def test_stop_wakes_sleeping_heartbeat(self):
        heartbeat = self._start_heartbeat(lambda: None, initial_delay=60)
        with futures.ThreadPoolExecutor(max_workers=1) as executor:
            stopped = executor.submit(self.functional_test.stop)
            try:
                stopped.result(timeout=5)
            finally:
                heartbeat.stop()
        # Repeated cleanup must be harmless, including after a restart.
        self.functional_test.stop()

    def _test_waits_for_heartbeat(self, cleanup):
        entered = threading.Event()
        release = threading.Event()
        finished = threading.Event()

        def report_state():
            entered.set()
            release.wait()
            finished.set()

        heartbeat = self._start_heartbeat(report_state)
        self.addCleanup(release.set)
        self.assertTrue(entered.wait(5))

        def stop_connection(*args, **kwargs):
            self.assertTrue(finished.is_set())
            return True

        self.driver.nb_synchronizer.stop.side_effect = stop_connection
        self.driver.sb_synchronizer.stop.side_effect = stop_connection
        for api in (self.driver.nb_ovn, self.driver.sb_ovn):
            api.ovsdb_connection.stop.side_effect = stop_connection

        with futures.ThreadPoolExecutor(max_workers=1) as executor:
            stopped = executor.submit(cleanup)
            try:
                self.assertRaises(futures.TimeoutError,
                                  stopped.result, timeout=0.1)
                release.set()
                stopped.result(timeout=5)
            finally:
                release.set()
                heartbeat.stop()

    def test_stop_finishes_heartbeat_before_closing_connections(self):
        self._test_waits_for_heartbeat(self.functional_test.stop)

    def test_maintenance_worker_stop_finishes_heartbeat(self):
        worker = self.driver.get_workers()[0]
        self._test_waits_for_heartbeat(worker.stop)
        worker.stop()

    def test_teardown_finishes_heartbeat_before_cleanups(self):
        self._test_waits_for_heartbeat(self.functional_test.tearDown)
        # Synchronizer cleanups can run before the fixture's stop callback.
        self.driver.nb_synchronizer.stop()
