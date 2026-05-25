# Copyright 2015 Mirantis Inc.
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

from unittest import mock

from oslo_concurrency import processutils
from oslo_config import cfg

from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import worker as \
    ovn_worker
from neutron import service as neutron_service
from neutron.tests import base


class TestServiceHelpers(base.BaseTestCase):

    def test_get_workers(self):
        num_workers = neutron_service._get_worker_count()
        self.assertGreaterEqual(num_workers, 1)
        self.assertLessEqual(num_workers, processutils.get_worker_count())


class TestRpcWorker(base.BaseTestCase):

    @mock.patch("neutron.policy.refresh")
    @mock.patch("neutron.common.config.setup_logging")
    def _test_reset(self, worker_service, setup_logging_mock, refresh_mock):
        worker_service.reset()

        setup_logging_mock.assert_called_once_with()
        refresh_mock.assert_called_once_with()

    def test_reset(self):
        _plugin = mock.Mock()

        rpc_worker = neutron_service.RpcWorker(_plugin)
        self._test_reset(rpc_worker)


class TestPreparePeriodicWorkers(base.BaseTestCase):

    def test_groupable_workers_wrapped(self):
        periodic_worker = mock.Mock(worker_process_count=0)
        rpc_worker = neutron_service.RpcWorker([mock.Mock()],
                                               worker_process_count=0)
        process_worker = mock.Mock(worker_process_count=2)
        maintenance_worker = ovn_worker.MaintenanceWorker()

        with mock.patch.object(neutron_service, 'AllServicesNeutronWorker') \
                as all_services_worker:
            services_worker = all_services_worker.return_value
            prepared = neutron_service._prepare_periodic_workers([
                periodic_worker, rpc_worker, process_worker,
                maintenance_worker])

        all_services_worker.assert_called_once_with(
            [periodic_worker, rpc_worker])
        self.assertEqual([process_worker, services_worker], prepared)

    def test_no_groupable_workers(self):
        process_worker = mock.Mock(worker_process_count=1)

        with mock.patch.object(neutron_service, 'AllServicesNeutronWorker') \
                as all_services_worker:
            prepared = neutron_service._prepare_periodic_workers(
                [process_worker])

        all_services_worker.assert_not_called()
        self.assertEqual([process_worker], prepared)


class TestStartPeriodicWorkers(base.BaseTestCase):

    @mock.patch.object(neutron_service.registry, 'publish')
    @mock.patch.object(neutron_service, '_start_workers')
    @mock.patch.object(neutron_service, '_prepare_periodic_workers')
    @mock.patch.object(neutron_service, '_get_plugins_workers')
    def test_prepare_and_start(
            self, get_workers, prepare_workers, start_workers, publish):
        plugin_workers = [mock.Mock()]
        prepared_workers = [mock.Mock()]
        launcher = start_workers.return_value
        get_workers.return_value = plugin_workers
        prepare_workers.return_value = prepared_workers

        self.assertIs(launcher, neutron_service.start_periodic_workers())

        prepare_workers.assert_called_once_with(plugin_workers)
        start_workers.assert_called_once_with(prepared_workers)
        publish.assert_called_once_with(
            neutron_service.resources.PROCESS,
            neutron_service.events.AFTER_SPAWN, None)


class TestRunRpcWorkers(base.BaseTestCase):
    def setUp(self):
        super().setUp()
        self.worker_count = neutron_service._get_worker_count()

    def _test_rpc_workers(self, config_value, expected_passed_value):
        if config_value is not None:
            cfg.CONF.set_override('rpc_workers', config_value)
        with mock.patch('neutron.service.RpcWorker') as mock_rpc_worker:
            with mock.patch('neutron.service.RpcReportsWorker'):
                neutron_service._get_rpc_workers(plugin=mock.Mock())
        init_call = mock_rpc_worker.call_args
        if expected_passed_value > 0:
            expected_call = mock.call(
                mock.ANY, worker_process_count=expected_passed_value)
            self.assertEqual(expected_call, init_call)
        else:
            mock_rpc_worker.assert_not_called()

    def test_rpc_workers_zero(self):
        self._test_rpc_workers(0, 0)

    def test_rpc_workers_default_api_workers_default(self):
        workers = max(int(self.worker_count / 2), 1)
        self._test_rpc_workers(None, workers)

    def test_rpc_workers_default_api_workers_set(self):
        cfg.CONF.set_override('api_workers', 18)
        self._test_rpc_workers(None, 9)

    def test_rpc_workers_defined(self):
        self._test_rpc_workers(42, 42)
