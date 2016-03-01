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
from oslo_config import cfg
from ryu.services.protocols.bgp import bgpspeaker
from ryu.services.protocols.bgp.rtconf.neighbors import CONNECT_MODE_ACTIVE

from neutron.services.bgp.agent import config as bgp_config
from neutron.services.bgp.driver import exceptions as bgp_driver_exc
from neutron.services.bgp.driver.ryu import driver as ryu_driver
from neutron.tests import base

# Test variables for BGP Speaker
FAKE_LOCAL_AS1 = 12345
FAKE_LOCAL_AS2 = 23456
FAKE_ROUTER_ID = '1.1.1.1'

# Test variables for BGP Peer
FAKE_PEER_AS = 45678
FAKE_PEER_IP = '2.2.2.5'
FAKE_AUTH_TYPE = 'md5'
FAKE_PEER_PASSWORD = 'awesome'

# Test variables for Route
FAKE_ROUTE = '2.2.2.0/24'
FAKE_NEXTHOP = '5.5.5.5'


class TestRyuBgpDriver(base.BaseTestCase):

    def setUp(self):
        super(TestRyuBgpDriver, self).setUp()
        cfg.CONF.register_opts(bgp_config.BGP_PROTO_CONFIG_OPTS, 'BGP')
        cfg.CONF.set_override('bgp_router_id', FAKE_ROUTER_ID, 'BGP')
        self.ryu_bgp_driver = ryu_driver.RyuBgpDriver(cfg.CONF.BGP)
        mock_ryu_speaker_p = mock.patch.object(bgpspeaker, 'BGPSpeaker')
        self.mock_ryu_speaker = mock_ryu_speaker_p.start()

    def test_add_new_bgp_speaker(self):
        self.ryu_bgp_driver.add_bgp_speaker(FAKE_LOCAL_AS1)
        self.assertEqual(1,
                self.ryu_bgp_driver.cache.get_hosted_bgp_speakers_count())
        self.mock_ryu_speaker.assert_called_once_with(
                 as_number=FAKE_LOCAL_AS1, router_id=FAKE_ROUTER_ID,
                 bgp_server_port=0,
                 best_path_change_handler=ryu_driver.best_path_change_cb,
                 peer_down_handler=ryu_driver.bgp_peer_down_cb,
                 peer_up_handler=ryu_driver.bgp_peer_up_cb)

    def test_remove_bgp_speaker(self):
        self.ryu_bgp_driver.add_bgp_speaker(FAKE_LOCAL_AS1)
        self.assertEqual(1,
                self.ryu_bgp_driver.cache.get_hosted_bgp_speakers_count())
        speaker = self.ryu_bgp_driver.cache.get_bgp_speaker(FAKE_LOCAL_AS1)
        self.ryu_bgp_driver.delete_bgp_speaker(FAKE_LOCAL_AS1)
        self.assertEqual(0,
                self.ryu_bgp_driver.cache.get_hosted_bgp_speakers_count())
        self.assertEqual(1, speaker.shutdown.call_count)

    def test_add_bgp_peer_without_password(self):
        self.ryu_bgp_driver.add_bgp_speaker(FAKE_LOCAL_AS1)
        self.assertEqual(1,
                self.ryu_bgp_driver.cache.get_hosted_bgp_speakers_count())
        self.ryu_bgp_driver.add_bgp_peer(FAKE_LOCAL_AS1,
                                         FAKE_PEER_IP,
                                         FAKE_PEER_AS)
        speaker = self.ryu_bgp_driver.cache.get_bgp_speaker(FAKE_LOCAL_AS1)
        speaker.neighbor_add.assert_called_once_with(
                                            address=FAKE_PEER_IP,
                                            remote_as=FAKE_PEER_AS,
                                            password=None,
                                            connect_mode=CONNECT_MODE_ACTIVE)

    def test_add_bgp_peer_with_password(self):
        self.ryu_bgp_driver.add_bgp_speaker(FAKE_LOCAL_AS1)
        self.assertEqual(1,
                self.ryu_bgp_driver.cache.get_hosted_bgp_speakers_count())
        self.ryu_bgp_driver.add_bgp_peer(FAKE_LOCAL_AS1,
                                         FAKE_PEER_IP,
                                         FAKE_PEER_AS,
                                         FAKE_AUTH_TYPE,
                                         FAKE_PEER_PASSWORD)
        speaker = self.ryu_bgp_driver.cache.get_bgp_speaker(FAKE_LOCAL_AS1)
        speaker.neighbor_add.assert_called_once_with(
                                             address=FAKE_PEER_IP,
                                             remote_as=FAKE_PEER_AS,
                                             password=FAKE_PEER_PASSWORD,
                                             connect_mode=CONNECT_MODE_ACTIVE)

    def test_remove_bgp_peer(self):
        self.ryu_bgp_driver.add_bgp_speaker(FAKE_LOCAL_AS1)
        self.assertEqual(1,
                self.ryu_bgp_driver.cache.get_hosted_bgp_speakers_count())
        self.ryu_bgp_driver.delete_bgp_peer(FAKE_LOCAL_AS1, FAKE_PEER_IP)
        speaker = self.ryu_bgp_driver.cache.get_bgp_speaker(FAKE_LOCAL_AS1)
        speaker.neighbor_del.assert_called_once_with(address=FAKE_PEER_IP)

    def test_advertise_route(self):
        self.ryu_bgp_driver.add_bgp_speaker(FAKE_LOCAL_AS1)
        self.assertEqual(1,
                self.ryu_bgp_driver.cache.get_hosted_bgp_speakers_count())
        self.ryu_bgp_driver.advertise_route(FAKE_LOCAL_AS1,
                                            FAKE_ROUTE,
                                            FAKE_NEXTHOP)
        speaker = self.ryu_bgp_driver.cache.get_bgp_speaker(FAKE_LOCAL_AS1)
        speaker.prefix_add.assert_called_once_with(prefix=FAKE_ROUTE,
                                                   next_hop=FAKE_NEXTHOP)

    def test_withdraw_route(self):
        self.ryu_bgp_driver.add_bgp_speaker(FAKE_LOCAL_AS1)
        self.assertEqual(1,
                self.ryu_bgp_driver.cache.get_hosted_bgp_speakers_count())
        self.ryu_bgp_driver.withdraw_route(FAKE_LOCAL_AS1, FAKE_ROUTE)
        speaker = self.ryu_bgp_driver.cache.get_bgp_speaker(FAKE_LOCAL_AS1)
        speaker.prefix_del.assert_called_once_with(prefix=FAKE_ROUTE)

    def test_add_same_bgp_speakers_twice(self):
        self.ryu_bgp_driver.add_bgp_speaker(FAKE_LOCAL_AS1)
        self.assertRaises(bgp_driver_exc.BgpSpeakerAlreadyScheduled,
                          self.ryu_bgp_driver.add_bgp_speaker, FAKE_LOCAL_AS1)

    def test_add_different_bgp_speakers_when_one_already_added(self):
        self.ryu_bgp_driver.add_bgp_speaker(FAKE_LOCAL_AS1)
        self.assertRaises(bgp_driver_exc.BgpSpeakerMaxScheduled,
                          self.ryu_bgp_driver.add_bgp_speaker,
                          FAKE_LOCAL_AS2)

    def test_add_bgp_speaker_with_invalid_asnum_paramtype(self):
        self.assertRaises(bgp_driver_exc.InvalidParamType,
                          self.ryu_bgp_driver.add_bgp_speaker, '12345')

    def test_add_bgp_speaker_with_invalid_asnum_range(self):
        self.assertRaises(bgp_driver_exc.InvalidParamRange,
                          self.ryu_bgp_driver.add_bgp_speaker, -1)
        self.assertRaises(bgp_driver_exc.InvalidParamRange,
                          self.ryu_bgp_driver.add_bgp_speaker, 65536)

    def test_add_bgp_peer_with_invalid_paramtype(self):
        # Test with an invalid asnum data-type
        self.ryu_bgp_driver.add_bgp_speaker(FAKE_LOCAL_AS1)
        self.assertRaises(bgp_driver_exc.InvalidParamType,
                          self.ryu_bgp_driver.add_bgp_peer,
                          FAKE_LOCAL_AS1, FAKE_PEER_IP, '12345')
        # Test with an invalid auth-type and an invalid password
        self.assertRaises(bgp_driver_exc.InvalidParamType,
                          self.ryu_bgp_driver.add_bgp_peer,
                          FAKE_LOCAL_AS1, FAKE_PEER_IP, FAKE_PEER_AS,
                          'sha-1', 1234)
        # Test with an invalid auth-type and a valid password
        self.assertRaises(bgp_driver_exc.InvaildAuthType,
                          self.ryu_bgp_driver.add_bgp_peer,
                          FAKE_LOCAL_AS1, FAKE_PEER_IP, FAKE_PEER_AS,
                          'hmac-md5', FAKE_PEER_PASSWORD)
        # Test with none auth-type and a valid password
        self.assertRaises(bgp_driver_exc.InvaildAuthType,
                          self.ryu_bgp_driver.add_bgp_peer,
                          FAKE_LOCAL_AS1, FAKE_PEER_IP, FAKE_PEER_AS,
                          'none', FAKE_PEER_PASSWORD)
        # Test with none auth-type and an invalid password
        self.assertRaises(bgp_driver_exc.InvalidParamType,
                          self.ryu_bgp_driver.add_bgp_peer,
                          FAKE_LOCAL_AS1, FAKE_PEER_IP, FAKE_PEER_AS,
                          'none', 1234)
        # Test with a valid auth-type and no password
        self.assertRaises(bgp_driver_exc.PasswordNotSpecified,
                          self.ryu_bgp_driver.add_bgp_peer,
                          FAKE_LOCAL_AS1, FAKE_PEER_IP, FAKE_PEER_AS,
                          FAKE_AUTH_TYPE, None)

    def test_add_bgp_peer_with_invalid_asnum_range(self):
        self.ryu_bgp_driver.add_bgp_speaker(FAKE_LOCAL_AS1)
        self.assertRaises(bgp_driver_exc.InvalidParamRange,
                          self.ryu_bgp_driver.add_bgp_peer,
                          FAKE_LOCAL_AS1, FAKE_PEER_IP, -1)
        self.assertRaises(bgp_driver_exc.InvalidParamRange,
                          self.ryu_bgp_driver.add_bgp_peer,
                          FAKE_LOCAL_AS1, FAKE_PEER_IP, 65536)

    def test_add_bgp_peer_without_adding_speaker(self):
        self.assertRaises(bgp_driver_exc.BgpSpeakerNotAdded,
                          self.ryu_bgp_driver.add_bgp_peer,
                          FAKE_LOCAL_AS1, FAKE_PEER_IP, FAKE_PEER_AS)

    def test_remove_bgp_peer_with_invalid_paramtype(self):
        self.ryu_bgp_driver.add_bgp_speaker(FAKE_LOCAL_AS1)
        self.assertRaises(bgp_driver_exc.InvalidParamType,
                          self.ryu_bgp_driver.delete_bgp_peer,
                          FAKE_LOCAL_AS1, 12345)

    def test_remove_bgp_peer_without_adding_speaker(self):
        self.assertRaises(bgp_driver_exc.BgpSpeakerNotAdded,
                          self.ryu_bgp_driver.delete_bgp_peer,
                          FAKE_LOCAL_AS1, FAKE_PEER_IP)

    def test_advertise_route_with_invalid_paramtype(self):
        self.ryu_bgp_driver.add_bgp_speaker(FAKE_LOCAL_AS1)
        self.assertRaises(bgp_driver_exc.InvalidParamType,
                          self.ryu_bgp_driver.advertise_route,
                          FAKE_LOCAL_AS1, 12345, FAKE_NEXTHOP)
        self.assertRaises(bgp_driver_exc.InvalidParamType,
                          self.ryu_bgp_driver.advertise_route,
                          FAKE_LOCAL_AS1, FAKE_ROUTE, 12345)

    def test_advertise_route_without_adding_speaker(self):
        self.assertRaises(bgp_driver_exc.BgpSpeakerNotAdded,
                          self.ryu_bgp_driver.advertise_route,
                          FAKE_LOCAL_AS1, FAKE_ROUTE, FAKE_NEXTHOP)

    def test_withdraw_route_with_invalid_paramtype(self):
        self.ryu_bgp_driver.add_bgp_speaker(FAKE_LOCAL_AS1)
        self.assertRaises(bgp_driver_exc.InvalidParamType,
                          self.ryu_bgp_driver.withdraw_route,
                          FAKE_LOCAL_AS1, 12345)
        self.assertRaises(bgp_driver_exc.InvalidParamType,
                          self.ryu_bgp_driver.withdraw_route,
                          FAKE_LOCAL_AS1, 12345)

    def test_withdraw_route_without_adding_speaker(self):
        self.assertRaises(bgp_driver_exc.BgpSpeakerNotAdded,
                          self.ryu_bgp_driver.withdraw_route,
                          FAKE_LOCAL_AS1, FAKE_ROUTE)

    def test_add_multiple_bgp_speakers(self):
        self.ryu_bgp_driver.add_bgp_speaker(FAKE_LOCAL_AS1)
        self.assertEqual(1,
                self.ryu_bgp_driver.cache.get_hosted_bgp_speakers_count())
        self.assertRaises(bgp_driver_exc.BgpSpeakerMaxScheduled,
                          self.ryu_bgp_driver.add_bgp_speaker,
                          FAKE_LOCAL_AS2)
        self.assertRaises(bgp_driver_exc.BgpSpeakerNotAdded,
                          self.ryu_bgp_driver.delete_bgp_speaker,
                          FAKE_LOCAL_AS2)
        self.assertEqual(1,
                self.ryu_bgp_driver.cache.get_hosted_bgp_speakers_count())
        self.ryu_bgp_driver.delete_bgp_speaker(FAKE_LOCAL_AS1)
        self.assertEqual(0,
                self.ryu_bgp_driver.cache.get_hosted_bgp_speakers_count())
