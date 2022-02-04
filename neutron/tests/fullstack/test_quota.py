# Copyright (c) 2022 Red Hat, Inc.
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

from oslo_utils import uuidutils

from neutron.conf import quota as quota_conf
from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import environment
from neutron.tests.unit import testlib_api

load_tests = testlib_api.module_load_tests


class TestQuota(base.BaseFullStackTestCase):

    scenarios = [
        ('DbQuotaDriver',
         {'quota_driver': quota_conf.QUOTA_DB_DRIVER_LEGACY}),
        ('DbQuotaNoLockDriver',
         {'quota_driver': quota_conf.QUOTA_DB_DRIVER_NO_LOCK}),
        ('DbQuotaDriverNull',
         {'quota_driver': quota_conf.QUOTA_DB_DRIVER_NULL}),
    ]

    def setUp(self, *args):
        host_descriptions = [environment.HostDescription()]
        env = environment.Environment(environment.EnvironmentDescription(
            quota_driver=self.quota_driver), host_descriptions)
        super().setUp(env)
        self.tenant_id = uuidutils.generate_uuid()

    def test_create_network_and_port(self):
        network = self.safe_client.create_network(self.tenant_id)
        self.safe_client.create_subnet(self.tenant_id, network['id'],
                                       '20.0.0.0/24')
        port = self.safe_client.create_port(self.tenant_id, network['id'])
        port_id = port['id']
        port = self.safe_client.client.list_ports(id=port_id)['ports'][0]
        self.assertEqual(port_id, port['id'])
