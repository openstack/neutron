# Copyright 2016 Huawei Technologies India Pvt. Ltd.
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

from neutron.api.rpc.agentnotifiers import bgp_dr_rpc_agent_api
from neutron import context
from neutron.tests import base


class TestBgpDrAgentNotifyApi(base.BaseTestCase):

    def setUp(self):
        super(TestBgpDrAgentNotifyApi, self).setUp()
        self.notifier = (
            bgp_dr_rpc_agent_api.BgpDrAgentNotifyApi())

        mock_cast_p = mock.patch.object(self.notifier,
                                        '_notification_host_cast')
        self.mock_cast = mock_cast_p.start()
        mock_call_p = mock.patch.object(self.notifier,
                                        '_notification_host_call')
        self.mock_call = mock_call_p.start()
        self.context = context.get_admin_context()
        self.host = 'host-1'

    def test_notify_dragent_bgp_routes_advertisement(self):
        bgp_speaker_id = 'bgp-speaker-1'
        routes = [{'destination': '1.1.1.1', 'next_hop': '2.2.2.2'}]
        self.notifier.bgp_routes_advertisement(self.context, bgp_speaker_id,
                                               routes, self.host)
        self.assertEqual(1, self.mock_cast.call_count)
        self.assertEqual(0, self.mock_call.call_count)

    def test_notify_dragent_bgp_routes_withdrawal(self):
        bgp_speaker_id = 'bgp-speaker-1'
        routes = [{'destination': '1.1.1.1'}]
        self.notifier.bgp_routes_withdrawal(self.context, bgp_speaker_id,
                                            routes, self.host)
        self.assertEqual(1, self.mock_cast.call_count)
        self.assertEqual(0, self.mock_call.call_count)

    def test_notify_bgp_peer_disassociated(self):
        bgp_speaker_id = 'bgp-speaker-1'
        bgp_peer_ip = '1.1.1.1'
        self.notifier.bgp_peer_disassociated(self.context, bgp_speaker_id,
                                             bgp_peer_ip, self.host)
        self.assertEqual(1, self.mock_cast.call_count)
        self.assertEqual(0, self.mock_call.call_count)

    def test_notify_bgp_peer_associated(self):
        bgp_speaker_id = 'bgp-speaker-1'
        bgp_peer_id = 'bgp-peer-1'
        self.notifier.bgp_peer_associated(self.context, bgp_speaker_id,
                                          bgp_peer_id, self.host)
        self.assertEqual(1, self.mock_cast.call_count)
        self.assertEqual(0, self.mock_call.call_count)

    def test_notify_bgp_speaker_created(self):
        bgp_speaker_id = 'bgp-speaker-1'
        self.notifier.bgp_speaker_created(self.context, bgp_speaker_id,
                                          self.host)
        self.assertEqual(1, self.mock_cast.call_count)
        self.assertEqual(0, self.mock_call.call_count)

    def test_notify_bgp_speaker_removed(self):
        bgp_speaker_id = 'bgp-speaker-1'
        self.notifier.bgp_speaker_removed(self.context, bgp_speaker_id,
                                          self.host)
        self.assertEqual(1, self.mock_cast.call_count)
        self.assertEqual(0, self.mock_call.call_count)
