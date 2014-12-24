# Copyright (c) 2015 OpenStack Foundation.
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

import mock

from neutron.api.rpc.handlers import dvr_rpc
from neutron.tests import base


class DVRServerRpcApiTestCase(base.BaseTestCase):

    def setUp(self):
        self.client_p = mock.patch.object(dvr_rpc.n_rpc, "get_client")
        self.client = self.client_p.start()
        self.rpc = dvr_rpc.DVRServerRpcApi('fake_topic')
        self.mock_cctxt = self.rpc.client.prepare.return_value
        self.ctxt = mock.ANY
        super(DVRServerRpcApiTestCase, self).setUp()

    def test_get_dvr_mac_address_by_host(self):
        self.rpc.get_dvr_mac_address_by_host(self.ctxt, 'foo_host')
        self.mock_cctxt.call.assert_called_with(
            self.ctxt, 'get_dvr_mac_address_by_host', host='foo_host')

    def test_get_dvr_mac_address_list(self):
        self.rpc.get_dvr_mac_address_list(self.ctxt)
        self.mock_cctxt.call.assert_called_with(
            self.ctxt, 'get_dvr_mac_address_list')

    def test_get_ports_on_host_by_subnet(self):
        self.rpc.get_ports_on_host_by_subnet(
            self.ctxt, 'foo_host', 'foo_subnet')
        self.mock_cctxt.call.assert_called_with(
            self.ctxt, 'get_ports_on_host_by_subnet',
            host='foo_host', subnet='foo_subnet')

    def test_get_subnet_for_dvr(self):
        self.rpc.get_subnet_for_dvr(self.ctxt, 'foo_subnet')
        self.mock_cctxt.call.assert_called_with(
            self.ctxt, 'get_subnet_for_dvr',
            subnet='foo_subnet')
