# Copyright (c) 2016 OpenStack Foundation.
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

from neutron_lib import rpc

from neutron.api.rpc.agentnotifiers import l3_rpc_agent_api
from neutron.tests import base


class TestL3AgentNotifyAPI(base.BaseTestCase):

    def setUp(self):
        super(TestL3AgentNotifyAPI, self).setUp()
        self.rpc_client_mock = mock.patch.object(
            rpc, 'get_client').start().return_value
        self.l3_notifier = l3_rpc_agent_api.L3AgentNotifyAPI()

    def _test_arp_update(self, method):
        arp_table = {'ip_address': '1.1.1.1',
                     'mac_address': '22:f1:6c:9c:79:4a',
                     'subnet_id': 'subnet_id'}
        router_id = 'router_id'
        getattr(self.l3_notifier, method)(mock.Mock(), router_id, arp_table)
        self.rpc_client_mock.prepare.assert_called_once_with(
            fanout=True, version='1.2')
        cctxt = self.rpc_client_mock.prepare.return_value
        cctxt.cast.assert_called_once_with(
            mock.ANY, method,
            payload={'router_id': router_id, 'arp_table': arp_table})

    def test_add_arp_entry(self):
        self._test_arp_update('add_arp_entry')

    def test_del_arp_entry(self):
        self._test_arp_update('del_arp_entry')
