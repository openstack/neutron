# Copyright (c) 2013 OpenStack, LLC.
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
#
# @author: Salvatore Orlando, VMware

import json
import os

import mock
import unittest2 as unittest

from quantum.openstack.common import log as logging
from quantum.plugins.nicira.nicira_nvp_plugin import NvpApiClient
from quantum.plugins.nicira.nicira_nvp_plugin import nvp_cluster
from quantum.plugins.nicira.nicira_nvp_plugin import nvplib
import quantum.plugins.nicira.nicira_nvp_plugin as nvp_plugin
from quantum.tests.unit.nicira import fake_nvpapiclient
from quantum.tests.unit import test_api_v2

LOG = logging.getLogger(__name__)
NICIRA_PKG_PATH = nvp_plugin.__name__
_uuid = test_api_v2._uuid


class TestNvplibNatRules(unittest.TestCase):

    def setUp(self):
        # mock nvp api client
        etc_path = os.path.join(os.path.dirname(__file__), 'etc')
        self.fc = fake_nvpapiclient.FakeClient(etc_path)
        self.mock_nvpapi = mock.patch('%s.NvpApiClient.NVPApiHelper'
                                      % NICIRA_PKG_PATH, autospec=True)
        instance = self.mock_nvpapi.start()

        def _fake_request(*args, **kwargs):
            return self.fc.fake_request(*args, **kwargs)

        instance.return_value.request.side_effect = _fake_request
        self.fake_cluster = nvp_cluster.NVPCluster('fake-cluster')
        self.fake_cluster.add_controller('1.1.1.1', '999', 'foo', 'bar',
                                         9, 9, 9, 9, _uuid())
        self.fake_cluster.api_client = NvpApiClient.NVPApiHelper(
            ('1.1.1.1', '999', True),
            self.fake_cluster.user, self.fake_cluster.password,
            self.fake_cluster.request_timeout, self.fake_cluster.http_timeout,
            self.fake_cluster.retries, self.fake_cluster.redirects)

        super(TestNvplibNatRules, self).setUp()

    def tearDown(self):
        self.fc.reset_all()
        self.mock_nvpapi.stop()

    def _test_create_lrouter_dnat_rule(self, func):
        tenant_id = 'pippo'
        lrouter = nvplib.create_lrouter(self.fake_cluster,
                                        tenant_id,
                                        'fake_router',
                                        '192.168.0.1')
        nat_rule = func(self.fake_cluster, lrouter['uuid'], '10.0.0.99',
                        match_criteria={'destination_ip_addresses':
                                        '192.168.0.5'})
        uri = nvplib._build_uri_path(nvplib.LROUTERNAT_RESOURCE,
                                     nat_rule['uuid'],
                                     lrouter['uuid'])
        return json.loads(nvplib.do_single_request("GET", uri,
                                                   cluster=self.fake_cluster))

    def test_create_lrouter_dnat_rule_v2(self):
        resp_obj = self._test_create_lrouter_dnat_rule(
            nvplib.create_lrouter_dnat_rule_v2)
        self.assertEquals('DestinationNatRule', resp_obj['type'])
        self.assertEquals('192.168.0.5',
                          resp_obj['match']['destination_ip_addresses'])

    def test_create_lrouter_dnat_rule_v3(self):
        resp_obj = self._test_create_lrouter_dnat_rule(
            nvplib.create_lrouter_dnat_rule_v2)
        # TODO(salvatore-orlando): Extend FakeNVPApiClient to deal with
        # different versions of NVP API
        self.assertEquals('DestinationNatRule', resp_obj['type'])
        self.assertEquals('192.168.0.5',
                          resp_obj['match']['destination_ip_addresses'])
