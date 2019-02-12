# Copyright 2014 Red Hat, Inc.
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

from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_service import service

from neutron import service as neutron_service
from neutron.tests.functional import base
from neutron.tests.functional import test_server


class TestService(base.BaseLoggingTestCase):

    def test_api_workers_default(self):
        # This value may end being scaled downward based on available RAM.
        self.assertGreaterEqual(processutils.get_worker_count(),
                                neutron_service._get_api_workers())

    def test_api_workers_from_config(self):
        cfg.CONF.set_override('api_workers', 1234)
        self.assertEqual(1234,
                         neutron_service._get_api_workers())


class TestServiceRestart(test_server.TestNeutronServer):

    def _start_service(self, host, binary, topic, manager, workers,
                       *args, **kwargs):
        server = neutron_service.Service(host, binary, topic, manager,
                                         *args, **kwargs)
        service.launch(cfg.CONF, server, workers).wait()
