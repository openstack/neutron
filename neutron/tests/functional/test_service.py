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

from neutron import service
from neutron.tests import base


class TestService(base.BaseTestCase):

    def test_api_workers_default(self):
        self.assertEqual(processutils.get_worker_count(),
                         service._get_api_workers())

    def test_api_workers_from_config(self):
        cfg.CONF.set_override('api_workers', 1234)
        self.assertEqual(1234,
                         service._get_api_workers())
