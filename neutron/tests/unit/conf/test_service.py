# Copyright (c) 2023 Red Hat Inc.
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

from oslo_config import cfg

from neutron.conf import service
from neutron.tests import base as tests_base


class GetRpcWorkers(tests_base.BaseTestCase):

    def test_no_previous_registration(self):
        self.assertIsNone(service.get_rpc_workers(conf=cfg.CONF))
        cfg.CONF.set_override('rpc_workers', 150)
        self.assertEqual(150, service.get_rpc_workers(conf=cfg.CONF))

    def test_previous_registration(self):
        service.register_service_opts(service.SERVICE_OPTS, conf=cfg.CONF)
        self.assertIsNone(service.get_rpc_workers(conf=cfg.CONF))
        cfg.CONF.set_override('rpc_workers', 200)
        self.assertEqual(200, service.get_rpc_workers(conf=cfg.CONF))
