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

import copy
import sys
import uuid

import eventlet
import mock
from oslo_config import cfg
import testtools

from neutron.common import config as common_config
from neutron import context
from neutron.services.bgp.agent import bgp_dragent
from neutron.services.bgp.agent import config as bgp_config
from neutron.services.bgp.agent import entry
from neutron.tests import base

HOSTNAME = 'hostname'
rpc_api = bgp_dragent.BgpDrPluginApi
BGP_PLUGIN = '%s.%s' % (rpc_api.__module__, rpc_api.__name__)

FAKE_BGPSPEAKER_UUID = str(uuid.uuid4())
FAKE_BGPPEER_UUID = str(uuid.uuid4())

FAKE_BGP_SPEAKER = {'id': FAKE_BGPSPEAKER_UUID,
                    'local_as': 12345,
                    'peers': [{'remote_as': '2345',
                               'peer_ip': '1.1.1.1',
                               'auth_type': 'none',
                               'password': ''}],
                    'advertised_routes': []}

FAKE_BGP_PEER = {'id': FAKE_BGPPEER_UUID,
                 'remote_as': '2345',
                 'peer_ip': '1.1.1.1',
                 'auth_type': 'none',
                 'password': ''}

FAKE_ROUTE = {'id': FAKE_BGPSPEAKER_UUID,
              'destination': '2.2.2.2/32',
              'next_hop': '3.3.3.3'}

FAKE_ROUTES = {'routes': {'id': FAKE_BGPSPEAKER_UUID,
                          'destination': '2.2.2.2/32',
                          'next_hop': '3.3.3.3'}
               }


class TestBgpDrAgent(base.BaseTestCase):
    def setUp(self):
        super(TestBgpDrAgent, self).setUp()
        cfg.CONF.register_opts(bgp_config.BGP_DRIVER_OPTS, 'BGP')
        cfg.CONF.register_opts(bgp_config.BGP_PROTO_CONFIG_OPTS, 'BGP')
        mock_log_p = mock.patch.object(bgp_dragent, 'LOG')
        self.mock_log = mock_log_p.start()
        self.driver_cls_p = mock.patch(
            'neutron.services.bgp.agent.bgp_dragent.importutils.import_class')
        self.driver_cls = self.driver_cls_p.start()
        self.context = context.get_admin_context()

    def test_bgp_dragent_manager(self):
        state_rpc_str = 'neutron.agent.rpc.PluginReportStateAPI'
        # sync_state is needed for this test
        with mock.patch.object(bgp_dragent.BgpDrAgentWithStateReport,
                               'sync_state',
                               autospec=True) as mock_sync_state:
            with mock.patch(state_rpc_str) as state_rpc:
                with mock.patch.object(sys, 'argv') as sys_argv:
                    sys_argv.return_value = [
                        'bgp_dragent', '--config-file',
                        base.etcdir('neutron.conf')]
                    common_config.init(sys.argv[1:])
                    agent_mgr = bgp_dragent.BgpDrAgentWithStateReport(
                        'testhost')
                    eventlet.greenthread.sleep(1)
                    agent_mgr.after_start()
                    self.assertIsNotNone(len(mock_sync_state.mock_calls))
                    state_rpc.assert_has_calls(
                        [mock.call(mock.ANY),
                         mock.call().report_state(mock.ANY, mock.ANY,
                                                  mock.ANY)])

    def test_bgp_dragent_main_agent_manager(self):
        logging_str = 'neutron.agent.common.config.setup_logging'
        launcher_str = 'oslo_service.service.ServiceLauncher'
        with mock.patch(logging_str):
            with mock.patch.object(sys, 'argv') as sys_argv:
                with mock.patch(launcher_str) as launcher:
                    sys_argv.return_value = ['bgp_dragent', '--config-file',
                                             base.etcdir('neutron.conf')]
                    entry.main()
                    launcher.assert_has_calls(
                        [mock.call(cfg.CONF),
                         mock.call().launch_service(mock.ANY),
                         mock.call().wait()])

    def test_run_completes_single_pass(self):
        bgp_dr = bgp_dragent.BgpDrAgent(HOSTNAME)
        with mock.patch.object(bgp_dr, 'sync_state') as sync_state:
            bgp_dr.run()
            self.assertIsNotNone(len(sync_state.mock_calls))

    def test_after_start(self):
        bgp_dr = bgp_dragent.BgpDrAgent(HOSTNAME)
        with mock.patch.object(bgp_dr, 'sync_state') as sync_state:
            bgp_dr.after_start()
            self.assertIsNotNone(len(sync_state.mock_calls))

    def _test_sync_state_helper(self, bgp_speaker_list=None,
                                cached_info=None,
                                safe_configure_call_count=0,
                                sync_bgp_speaker_call_count=0,
                                remove_bgp_speaker_call_count=0,
                                remove_bgp_speaker_ids=None,
                                added_bgp_speakers=None,
                                synced_bgp_speakers=None):
        bgp_dr = bgp_dragent.BgpDrAgent(HOSTNAME)

        attrs_to_mock = dict(
            [(a, mock.MagicMock())
             for a in ['plugin_rpc', 'sync_bgp_speaker',
                       'safe_configure_dragent_for_bgp_speaker',
                       'remove_bgp_speaker_from_dragent']])

        with mock.patch.multiple(bgp_dr, **attrs_to_mock):
            if not cached_info:
                cached_info = {}
            if not added_bgp_speakers:
                added_bgp_speakers = []
            if not remove_bgp_speaker_ids:
                remove_bgp_speaker_ids = []
            if not synced_bgp_speakers:
                synced_bgp_speakers = []

            bgp_dr.plugin_rpc.get_bgp_speakers.return_value = bgp_speaker_list
            bgp_dr.cache.cache = cached_info
            bgp_dr.cache.clear_cache = mock.Mock()
            bgp_dr.sync_state(mock.ANY)

            self.assertEqual(
                remove_bgp_speaker_call_count,
                bgp_dr.remove_bgp_speaker_from_dragent.call_count)

            if remove_bgp_speaker_call_count:
                expected_calls = [mock.call(bgp_speaker_id)
                                  for bgp_speaker_id in remove_bgp_speaker_ids]
                bgp_dr.remove_bgp_speaker_from_dragent.assert_has_calls(
                    expected_calls)

            self.assertEqual(
                safe_configure_call_count,
                bgp_dr.safe_configure_dragent_for_bgp_speaker.call_count)

            if safe_configure_call_count:
                expected_calls = [mock.call(bgp_speaker)
                                  for bgp_speaker in added_bgp_speakers]
                bgp_dr.safe_configure_dragent_for_bgp_speaker.assert_has_calls(
                    expected_calls)

            self.assertEqual(sync_bgp_speaker_call_count,
                             bgp_dr.sync_bgp_speaker.call_count)

            if sync_bgp_speaker_call_count:
                expected_calls = [mock.call(bgp_speaker)
                                  for bgp_speaker in synced_bgp_speakers]
                bgp_dr.sync_bgp_speaker.assert_has_calls(expected_calls)

    def test_sync_state_bgp_speaker_added(self):
        bgp_speaker_list = [{'id': 'foo-id',
                             'local_as': 12345,
                             'peers': [],
                             'advertised_routes': []}]
        self._test_sync_state_helper(bgp_speaker_list=bgp_speaker_list,
                                     safe_configure_call_count=1,
                                     added_bgp_speakers=bgp_speaker_list)

    def test_sync_state_bgp_speaker_deleted(self):
        bgp_speaker_list = []
        cached_bgp_speaker = {'id': 'foo-id',
                              'local_as': 12345,
                              'peers': ['peer-1'],
                              'advertised_routes': []}
        cached_info = {'foo-id': cached_bgp_speaker}
        self._test_sync_state_helper(bgp_speaker_list=bgp_speaker_list,
                                     cached_info=cached_info,
                                     remove_bgp_speaker_call_count=1,
                                     remove_bgp_speaker_ids=['foo-id'])

    def test_sync_state_added_and_deleted(self):
        bgp_speaker_list = [{'id': 'foo-id',
                             'local_as': 12345,
                             'peers': [],
                             'advertised_routes': []}]
        cached_bgp_speaker = {'bgp_speaker': {'local_as': 12345},
                              'peers': ['peer-1'],
                              'advertised_routes': []}
        cached_info = {'bar-id': cached_bgp_speaker}

        self._test_sync_state_helper(bgp_speaker_list=bgp_speaker_list,
                                     cached_info=cached_info,
                                     remove_bgp_speaker_call_count=1,
                                     remove_bgp_speaker_ids=['bar-id'],
                                     safe_configure_call_count=1,
                                     added_bgp_speakers=bgp_speaker_list)

    def test_sync_state_added_and_synced(self):
        bgp_speaker_list = [{'id': 'foo-id',
                             'local_as': 12345,
                             'peers': [],
                             'advertised_routes': []},
                            {'id': 'bar-id', 'peers': ['peer-2'],
                             'advertised_routes': []},
                            {'id': 'temp-id', 'peers': ['temp-1'],
                                'advertised_routes': []}]

        cached_bgp_speaker = {'id': 'bar-id', 'bgp_speaker': {'id': 'bar-id'},
                              'peers': ['peer-1'],
                              'advertised_routes': []}
        cached_bgp_speaker_2 = {'id': 'temp-id',
                                'bgp_speaker': {'id': 'temp-id'},
                                'peers': ['temp-1'],
                                'advertised_routes': []}
        cached_info = {'bar-id': cached_bgp_speaker,
                       'temp-id': cached_bgp_speaker_2}

        self._test_sync_state_helper(bgp_speaker_list=bgp_speaker_list,
                                     cached_info=cached_info,
                                     safe_configure_call_count=1,
                                     added_bgp_speakers=[bgp_speaker_list[0]],
                                     sync_bgp_speaker_call_count=2,
                                     synced_bgp_speakers=[bgp_speaker_list[1],
                                                          bgp_speaker_list[2]]
                                     )

    def test_sync_state_added_synced_and_removed(self):
        bgp_speaker_list = [{'id': 'foo-id',
                             'local_as': 12345,
                             'peers': [],
                             'advertised_routes': []},
                            {'id': 'bar-id', 'peers': ['peer-2'],
                             'advertised_routes': []}]
        cached_bgp_speaker = {'id': 'bar-id',
                              'bgp_speaker': {'id': 'bar-id'},
                              'peers': ['peer-1'],
                              'advertised_routes': []}
        cached_bgp_speaker_2 = {'id': 'temp-id',
                                'bgp_speaker': {'id': 'temp-id'},
                                'peers': ['temp-1'],
                                'advertised_routes': []}
        cached_info = {'bar-id': cached_bgp_speaker,
                       'temp-id': cached_bgp_speaker_2}

        self._test_sync_state_helper(bgp_speaker_list=bgp_speaker_list,
                                     cached_info=cached_info,
                                     remove_bgp_speaker_call_count=1,
                                     remove_bgp_speaker_ids=['temp-id'],
                                     safe_configure_call_count=1,
                                     added_bgp_speakers=[bgp_speaker_list[0]],
                                     sync_bgp_speaker_call_count=1,
                                     synced_bgp_speakers=[bgp_speaker_list[1]])

    def _test_sync_bgp_speaker_helper(self, bgp_speaker, cached_info=None,
                                      remove_bgp_peer_call_count=0,
                                      removed_bgp_peer_ip_list=None,
                                      withdraw_route_call_count=0,
                                      withdraw_routes_list=None,
                                      add_bgp_peers_called=False,
                                      advertise_routes_called=False):
        if not cached_info:
            cached_info = {}
        if not removed_bgp_peer_ip_list:
            removed_bgp_peer_ip_list = []
        if not withdraw_routes_list:
            withdraw_routes_list = []

        bgp_dr = bgp_dragent.BgpDrAgent(HOSTNAME)

        attrs_to_mock = dict(
            [(a, mock.MagicMock())
             for a in ['remove_bgp_peer_from_bgp_speaker',
                       'add_bgp_peers_to_bgp_speaker',
                       'advertise_routes_via_bgp_speaker',
                       'withdraw_route_via_bgp_speaker']])

        with mock.patch.multiple(bgp_dr, **attrs_to_mock):
            bgp_dr.cache.cache = cached_info
            bgp_dr.sync_bgp_speaker(bgp_speaker)

            self.assertEqual(
                remove_bgp_peer_call_count,
                bgp_dr.remove_bgp_peer_from_bgp_speaker.call_count)

            if remove_bgp_peer_call_count:
                expected_calls = [mock.call(bgp_speaker['id'], peer_ip)
                                  for peer_ip in removed_bgp_peer_ip_list]
                bgp_dr.remove_bgp_peer_from_bgp_speaker.assert_has_calls(
                    expected_calls)

            self.assertEqual(add_bgp_peers_called,
                             bgp_dr.add_bgp_peers_to_bgp_speaker.called)

            if add_bgp_peers_called:
                bgp_dr.add_bgp_peers_to_bgp_speaker.assert_called_with(
                    bgp_speaker)

            self.assertEqual(
                withdraw_route_call_count,
                bgp_dr.withdraw_route_via_bgp_speaker.call_count)

            if withdraw_route_call_count:
                expected_calls = [mock.call(bgp_speaker['id'], 12345, route)
                                  for route in withdraw_routes_list]
                bgp_dr.withdraw_route_via_bgp_speaker.assert_has_calls(
                    expected_calls)

            self.assertEqual(advertise_routes_called,
                             bgp_dr.advertise_routes_via_bgp_speaker.called)

            if advertise_routes_called:
                bgp_dr.advertise_routes_via_bgp_speaker.assert_called_with(
                    bgp_speaker)

    def test_sync_bgp_speaker_bgp_peers_updated(self):
        peers = [{'id': 'peer-1', 'peer_ip': '1.1.1.1'},
                 {'id': 'peer-2', 'peer_ip': '2.2.2.2'}]
        bgp_speaker = {'id': 'foo-id',
                       'local_as': 12345,
                       'peers': peers,
                       'advertised_routes': []}

        cached_peers = {'1.1.1.1': {'id': 'peer-2', 'peer_ip': '1.1.1.1'},
                        '3.3.3.3': {'id': 'peer-3', 'peer_ip': '3.3.3.3'}}

        cached_bgp_speaker = {'foo-id': {'bgp_speaker': {'local_as': 12345},
                                         'peers': cached_peers,
                                         'advertised_routes': []}}
        self._test_sync_bgp_speaker_helper(
            bgp_speaker, cached_info=cached_bgp_speaker,
            remove_bgp_peer_call_count=1,
            removed_bgp_peer_ip_list=['3.3.3.3'],
            add_bgp_peers_called=True,
            advertise_routes_called=False)

    def test_sync_bgp_speaker_routes_updated(self):
        adv_routes = [{'destination': '10.0.0.0/24', 'next_hop': '1.1.1.1'},
                      {'destination': '20.0.0.0/24', 'next_hop': '2.2.2.2'}]
        bgp_speaker = {'id': 'foo-id',
                       'local_as': 12345,
                       'peers': {},
                       'advertised_routes': adv_routes}

        cached_adv_routes = [{'destination': '20.0.0.0/24',
                              'next_hop': '2.2.2.2'},
                             {'destination': '30.0.0.0/24',
                              'next_hop': '3.3.3.3'}]

        cached_bgp_speaker = {
            'foo-id': {'bgp_speaker': {'local_as': 12345},
                       'peers': {},
                       'advertised_routes': cached_adv_routes}}

        self._test_sync_bgp_speaker_helper(
            bgp_speaker, cached_info=cached_bgp_speaker,
            withdraw_route_call_count=1,
            withdraw_routes_list=[cached_adv_routes[1]],
            add_bgp_peers_called=False,
            advertise_routes_called=True)

    def test_sync_bgp_speaker_peers_routes_added(self):
        peers = [{'id': 'peer-1', 'peer_ip': '1.1.1.1'},
                 {'id': 'peer-2', 'peer_ip': '2.2.2.2'}]
        adv_routes = [{'destination': '10.0.0.0/24',
                       'next_hop': '1.1.1.1'},
                      {'destination': '20.0.0.0/24',
                       'next_hop': '2.2.2.2'}]
        bgp_speaker = {'id': 'foo-id',
                       'local_as': 12345,
                       'peers': peers,
                       'advertised_routes': adv_routes}

        cached_bgp_speaker = {
            'foo-id': {'bgp_speaker': {'local_as': 12345},
                       'peers': {},
                       'advertised_routes': []}}

        self._test_sync_bgp_speaker_helper(
            bgp_speaker, cached_info=cached_bgp_speaker,
            add_bgp_peers_called=True,
            advertise_routes_called=True)

    def test_sync_state_plugin_error(self):
        with mock.patch(BGP_PLUGIN) as plug:
            mock_plugin = mock.Mock()
            mock_plugin.get_bgp_speakers.side_effect = Exception
            plug.return_value = mock_plugin

            with mock.patch.object(bgp_dragent.LOG, 'error') as log:
                bgp_dr = bgp_dragent.BgpDrAgent(HOSTNAME)
                with mock.patch.object(bgp_dr,
                        'schedule_full_resync') as schedule_full_resync:
                    bgp_dr.sync_state(mock.ANY)

                    self.assertTrue(log.called)
                    self.assertTrue(schedule_full_resync.called)

    def test_periodic_resync(self):
        bgp_dr = bgp_dragent.BgpDrAgent(HOSTNAME)
        with mock.patch.object(bgp_dr,
                               '_periodic_resync_helper') as resync_helper:
            bgp_dr.periodic_resync(self.context)
            self.assertTrue(resync_helper.called)

    def test_periodic_resync_helper(self):
        bgp_dr = bgp_dragent.BgpDrAgent(HOSTNAME)
        bgp_dr.schedule_resync('foo reason', 'foo-id')
        with mock.patch.object(bgp_dr, 'sync_state') as sync_state:
            sync_state.side_effect = RuntimeError
            with testtools.ExpectedException(RuntimeError):
                bgp_dr._periodic_resync_helper(self.context)
            self.assertTrue(sync_state.called)
            self.assertEqual(len(bgp_dr.needs_resync_reasons), 0)

    def _test_add_bgp_peer_helper(self, bgp_speaker_id,
                                  bgp_peer, cached_bgp_speaker,
                                  put_bgp_peer_called=True):
        bgp_dr = bgp_dragent.BgpDrAgent(HOSTNAME)

        bgp_dr.cache.cache = cached_bgp_speaker
        with mock.patch.object(
                bgp_dr.cache, 'put_bgp_peer') as mock_put_bgp_peer:
            bgp_dr.add_bgp_peer_to_bgp_speaker('foo-id', 12345, bgp_peer)
            if put_bgp_peer_called:
                mock_put_bgp_peer.assert_called_once_with(
                    bgp_speaker_id, bgp_peer)
            else:
                self.assertFalse(mock_put_bgp_peer.called)

    def test_add_bgp_peer_not_cached(self):
        bgp_peer = {'peer_ip': '1.1.1.1', 'remote_as': 34567,
                    'auth_type': 'md5', 'password': 'abc'}
        cached_bgp_speaker = {'foo-id': {'bgp_speaker': {'local_as': 12345},
                                         'peers': {},
                                         'advertised_routes': []}}

        self._test_add_bgp_peer_helper('foo-id', bgp_peer, cached_bgp_speaker)

    def test_add_bgp_peer_already_cached(self):
        bgp_peer = {'peer_ip': '1.1.1.1', 'remote_as': 34567,
                    'auth_type': 'md5', 'password': 'abc'}
        cached_peers = {'1.1.1.1': {'peer_ip': '1.1.1.1', 'remote_as': 34567}}
        cached_bgp_speaker = {'foo-id': {'bgp_speaker': {'local_as': 12345},
                                         'peers': cached_peers,
                                         'advertised_routes': []}}

        self._test_add_bgp_peer_helper('foo-id', bgp_peer, cached_bgp_speaker,
                                       put_bgp_peer_called=False)

    def _test_advertise_route_helper(self, bgp_speaker_id,
                                     route, cached_bgp_speaker,
                                     put_adv_route_called=True):
        bgp_dr = bgp_dragent.BgpDrAgent(HOSTNAME)

        bgp_dr.cache.cache = cached_bgp_speaker
        with mock.patch.object(
                bgp_dr.cache, 'put_adv_route') as mock_put_adv_route:
            bgp_dr.advertise_route_via_bgp_speaker(bgp_speaker_id, 12345,
                                                   route)
            if put_adv_route_called:
                mock_put_adv_route.assert_called_once_with(
                    bgp_speaker_id, route)
            else:
                self.assertFalse(mock_put_adv_route.called)

    def test_advertise_route_helper_not_cached(self):
        route = {'destination': '10.0.0.0/24', 'next_hop': '1.1.1.1'}
        cached_bgp_speaker = {'foo-id': {'bgp_speaker': {'local_as': 12345},
                                         'peers': {},
                                         'advertised_routes': []}}

        self._test_advertise_route_helper('foo-id', route, cached_bgp_speaker,
                                          put_adv_route_called=True)

    def test_advertise_route_helper_already_cached(self):
        route = {'destination': '10.0.0.0/24', 'next_hop': '1.1.1.1'}
        cached_bgp_speaker = {'foo-id': {'bgp_speaker': {'local_as': 12345},
                                         'peers': {},
                                         'advertised_routes': [route]}}

        self._test_advertise_route_helper('foo-id', route, cached_bgp_speaker,
                                          put_adv_route_called=False)


class TestBgpDrAgentEventHandler(base.BaseTestCase):

    cache_cls = 'neutron.services.bgp.agent.bgp_dragent.BgpSpeakerCache'

    def setUp(self):
        super(TestBgpDrAgentEventHandler, self).setUp()
        cfg.CONF.register_opts(bgp_config.BGP_DRIVER_OPTS, 'BGP')
        cfg.CONF.register_opts(bgp_config.BGP_PROTO_CONFIG_OPTS, 'BGP')

        mock_log_p = mock.patch.object(bgp_dragent, 'LOG')
        self.mock_log = mock_log_p.start()

        self.plugin_p = mock.patch(BGP_PLUGIN)
        plugin_cls = self.plugin_p.start()
        self.plugin = mock.Mock()
        plugin_cls.return_value = self.plugin

        self.cache_p = mock.patch(self.cache_cls)
        cache_cls = self.cache_p.start()
        self.cache = mock.Mock()
        cache_cls.return_value = self.cache

        self.driver_cls_p = mock.patch(
            'neutron.services.bgp.agent.bgp_dragent.importutils.import_class')
        self.driver_cls = self.driver_cls_p.start()

        self.bgp_dr = bgp_dragent.BgpDrAgent(HOSTNAME)
        self.schedule_full_resync_p = mock.patch.object(
                                        self.bgp_dr, 'schedule_full_resync')
        self.schedule_full_resync = self.schedule_full_resync_p.start()
        self.context = mock.Mock()

    def test_bgp_speaker_create_end(self):
        payload = {'bgp_speaker': {'id': FAKE_BGPSPEAKER_UUID}}

        with mock.patch.object(self.bgp_dr,
                               'add_bgp_speaker_helper') as enable:
            self.bgp_dr.bgp_speaker_create_end(None, payload)
            enable.assert_called_once_with(FAKE_BGP_SPEAKER['id'])

    def test_bgp_peer_association_end(self):
        payload = {'bgp_peer': {'speaker_id': FAKE_BGPSPEAKER_UUID,
                                'peer_id': FAKE_BGPPEER_UUID}}

        with mock.patch.object(self.bgp_dr,
                               'add_bgp_peer_helper') as enable:
            self.bgp_dr.bgp_peer_association_end(None, payload)
            enable.assert_called_once_with(FAKE_BGP_SPEAKER['id'],
                                           FAKE_BGP_PEER['id'])

    def test_route_advertisement_end(self):
        routes = [{'destination': '2.2.2.2/32', 'next_hop': '3.3.3.3'},
                  {'destination': '4.4.4.4/32', 'next_hop': '5.5.5.5'}]
        payload = {'advertise_routes': {'speaker_id': FAKE_BGPSPEAKER_UUID,
                                        'routes': routes}}

        expected_calls = [mock.call(FAKE_BGP_SPEAKER['id'], routes)]

        with mock.patch.object(self.bgp_dr,
                               'add_routes_helper') as enable:
            self.bgp_dr.bgp_routes_advertisement_end(None, payload)
            enable.assert_has_calls(expected_calls)

    def test_add_bgp_speaker_helper(self):
        self.plugin.get_bgp_speaker_info.return_value = FAKE_BGP_SPEAKER
        add_bs_p = mock.patch.object(self.bgp_dr,
                                   'add_bgp_speaker_on_dragent')
        add_bs = add_bs_p.start()
        self.bgp_dr.add_bgp_speaker_helper(FAKE_BGP_SPEAKER['id'])
        self.plugin.assert_has_calls([
            mock.call.get_bgp_speaker_info(mock.ANY,
                                           FAKE_BGP_SPEAKER['id'])])
        add_bs.assert_called_once_with(FAKE_BGP_SPEAKER)

    def test_add_bgp_peer_helper(self):
        self.plugin.get_bgp_peer_info.return_value = FAKE_BGP_PEER
        add_bp_p = mock.patch.object(self.bgp_dr,
                                     'add_bgp_peer_to_bgp_speaker')
        add_bp = add_bp_p.start()
        self.bgp_dr.add_bgp_peer_helper(FAKE_BGP_SPEAKER['id'],
                                        FAKE_BGP_PEER['id'])
        self.plugin.assert_has_calls([
            mock.call.get_bgp_peer_info(mock.ANY,
                                        FAKE_BGP_PEER['id'])])
        self.assertEqual(1, add_bp.call_count)

    def test_add_routes_helper(self):
        add_rt_p = mock.patch.object(self.bgp_dr,
                                     'advertise_route_via_bgp_speaker')
        add_bp = add_rt_p.start()
        self.bgp_dr.add_routes_helper(FAKE_BGP_SPEAKER['id'], FAKE_ROUTES)
        self.assertEqual(1, add_bp.call_count)

    def test_bgp_speaker_remove_end(self):
        payload = {'bgp_speaker': {'id': FAKE_BGPSPEAKER_UUID}}

        with mock.patch.object(self.bgp_dr,
                               'remove_bgp_speaker_from_dragent') as disable:
            self.bgp_dr.bgp_speaker_remove_end(None, payload)
            disable.assert_called_once_with(FAKE_BGP_SPEAKER['id'])

    def test_bgp_peer_disassociation_end(self):
        payload = {'bgp_peer': {'speaker_id': FAKE_BGPSPEAKER_UUID,
                                'peer_ip': '1.1.1.1'}}

        with mock.patch.object(self.bgp_dr,
                               'remove_bgp_peer_from_bgp_speaker') as disable:
            self.bgp_dr.bgp_peer_disassociation_end(None, payload)
            disable.assert_called_once_with(FAKE_BGPSPEAKER_UUID,
                                            FAKE_BGP_PEER['peer_ip'])

    def test_bgp_routes_withdrawal_end(self):
        withdraw_routes = [{'destination': '2.2.2.2/32'},
                           {'destination': '3.3.3.3/32'}]
        payload = {'withdraw_routes': {'speaker_id': FAKE_BGPSPEAKER_UUID,
                                       'routes': withdraw_routes}}

        expected_calls = [mock.call(FAKE_BGP_SPEAKER['id'], withdraw_routes)]

        with mock.patch.object(self.bgp_dr,
                               'withdraw_routes_helper') as disable:
            self.bgp_dr.bgp_routes_withdrawal_end(None, payload)
            disable.assert_has_calls(expected_calls)


class TestBGPSpeakerCache(base.BaseTestCase):

    def setUp(self):
        super(TestBGPSpeakerCache, self).setUp()
        self.expected_cache = {FAKE_BGP_SPEAKER['id']:
                               {'bgp_speaker': FAKE_BGP_SPEAKER,
                                'peers': {},
                                'advertised_routes': []}}
        self.bs_cache = bgp_dragent.BgpSpeakerCache()

    def test_put_bgp_speaker(self):
        self.bs_cache.put_bgp_speaker(FAKE_BGP_SPEAKER)
        self.assertEqual(self.expected_cache, self.bs_cache.cache)

    def test_put_bgp_speaker_existing(self):
        prev_bs_info = {'id': 'foo-id'}
        with mock.patch.object(self.bs_cache,
                               'remove_bgp_speaker_by_id') as remove:
            self.bs_cache.cache[FAKE_BGP_SPEAKER['id']] = prev_bs_info
            self.bs_cache.put_bgp_speaker(FAKE_BGP_SPEAKER)
            remove.assert_called_once_with(prev_bs_info)
        self.assertEqual(self.expected_cache, self.bs_cache.cache)

    def remove_bgp_speaker_by_id(self):
        self.bs_cache.put_bgp_speaker(FAKE_BGP_SPEAKER)
        self.assertEqual(1, len(self.bs_cache.cache))
        self.bs_cache.remove_bgp_speaker_by_id(FAKE_BGP_SPEAKER['id'])
        self.assertEqual(0, len(self.bs_cache.cache))

    def test_get_bgp_speaker_by_id(self):
        self.bs_cache.put_bgp_speaker(FAKE_BGP_SPEAKER)

        self.assertEqual(
            FAKE_BGP_SPEAKER,
            self.bs_cache.get_bgp_speaker_by_id(FAKE_BGP_SPEAKER['id']))

    def test_get_bgp_speaker_ids(self):
        self.bs_cache.put_bgp_speaker(FAKE_BGP_SPEAKER)

        self.assertEqual([FAKE_BGP_SPEAKER['id']],
                         list(self.bs_cache.get_bgp_speaker_ids()))

    def _test_bgp_peer_helper(self, remove=False):
        self.bs_cache.put_bgp_speaker(FAKE_BGP_SPEAKER)
        self.bs_cache.put_bgp_peer(FAKE_BGP_SPEAKER['id'], FAKE_BGP_PEER)
        expected_cache = copy.deepcopy(self.expected_cache)
        expected_cache[FAKE_BGP_SPEAKER['id']]['peers'] = {
            FAKE_BGP_PEER['peer_ip']: FAKE_BGP_PEER}
        self.assertEqual(expected_cache, self.bs_cache.cache)

        if remove:
            self.bs_cache.remove_bgp_peer_by_ip(FAKE_BGP_SPEAKER['id'],
                                                'foo-ip')
            self.assertEqual(expected_cache, self.bs_cache.cache)

            self.bs_cache.remove_bgp_peer_by_ip(FAKE_BGP_SPEAKER['id'],
                                                FAKE_BGP_PEER['peer_ip'])
            self.assertEqual(self.expected_cache, self.bs_cache.cache)

    def test_put_bgp_peer(self):
        self._test_bgp_peer_helper()

    def test_remove_bgp_peer(self):
        self._test_bgp_peer_helper(remove=True)

    def _test_bgp_speaker_adv_route_helper(self, remove=False):
        self.bs_cache.put_bgp_speaker(FAKE_BGP_SPEAKER)
        self.bs_cache.put_adv_route(FAKE_BGP_SPEAKER['id'], FAKE_ROUTE)
        expected_cache = copy.deepcopy(self.expected_cache)
        expected_cache[FAKE_BGP_SPEAKER['id']]['advertised_routes'].append(
            FAKE_ROUTE)
        self.assertEqual(expected_cache, self.bs_cache.cache)

        fake_route_2 = copy.deepcopy(FAKE_ROUTE)
        fake_route_2['destination'] = '4.4.4.4/32'
        self.bs_cache.put_adv_route(FAKE_BGP_SPEAKER['id'], fake_route_2)

        expected_cache[FAKE_BGP_SPEAKER['id']]['advertised_routes'].append(
            fake_route_2)
        self.assertEqual(expected_cache, self.bs_cache.cache)

        if remove:
            self.bs_cache.remove_adv_route(FAKE_BGP_SPEAKER['id'],
                                           fake_route_2)
            expected_cache[FAKE_BGP_SPEAKER['id']]['advertised_routes'] = (
                [FAKE_ROUTE])
            self.assertEqual(expected_cache, self.bs_cache.cache)

            self.bs_cache.remove_adv_route(FAKE_BGP_SPEAKER['id'],
                                           FAKE_ROUTE)
            self.assertEqual(self.expected_cache, self.bs_cache.cache)

    def test_put_bgp_speaker_adv_route(self):
        self._test_bgp_speaker_adv_route_helper()

    def test_remove_bgp_speaker_adv_route(self):
        self._test_bgp_speaker_adv_route_helper(remove=True)

    def test_is_bgp_speaker_adv_route_present(self):
        self._test_bgp_speaker_adv_route_helper()
        self.assertTrue(self.bs_cache.is_route_advertised(
            FAKE_BGP_SPEAKER['id'], FAKE_ROUTE))
        self.assertFalse(self.bs_cache.is_route_advertised(
            FAKE_BGP_SPEAKER['id'], {'destination': 'foo-destination',
                                     'next_hop': 'foo-next-hop'}))
