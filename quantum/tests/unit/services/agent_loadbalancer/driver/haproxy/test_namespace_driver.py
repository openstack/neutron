# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 New Dream Network, LLC (DreamHost)
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
#
# @author: Mark McClain, DreamHost

import contextlib
import mock
import testtools

from quantum.plugins.services.agent_loadbalancer.drivers.haproxy import (
    namespace_driver
)


class TestHaproxyNSDriver(testtools.TestCase):
    def setUp(self):
        super(TestHaproxyNSDriver, self).setUp()

        self.vif_driver = mock.Mock()
        self.vip_plug_callback = mock.Mock()

        self.driver = namespace_driver.HaproxyNSDriver(
            'sudo',
            '/the/path',
            self.vif_driver,
            self.vip_plug_callback
        )

        self.fake_config = {
            'pool': {'id': 'pool_id'},
            'vip': {'id': 'vip_id', 'port': {'id': 'port_id'}}
        }

    def test_create(self):
        with mock.patch.object(self.driver, '_plug') as plug:
            with mock.patch.object(self.driver, '_spawn') as spawn:
                self.driver.create(self.fake_config)

                plug.assert_called_once_with(
                    'qlbaas-pool_id', {'id': 'port_id'}
                )
                spawn.assert_called_once_with(self.fake_config)

    def test_update(self):
        with contextlib.nested(
            mock.patch.object(self.driver, '_get_state_file_path'),
            mock.patch.object(self.driver, '_spawn'),
            mock.patch('__builtin__.open')
        ) as (gsp, spawn, mock_open):
            mock_open.return_value = ['5']

            self.driver.update(self.fake_config)

            mock_open.assert_called_once_with(gsp.return_value, 'r')
            spawn.assert_called_once_with(self.fake_config, ['-sf', '5'])

    def test_spawn(self):
        with contextlib.nested(
            mock.patch.object(namespace_driver.hacfg, 'save_config'),
            mock.patch.object(self.driver, '_get_state_file_path'),
            mock.patch('quantum.agent.linux.ip_lib.IPWrapper')
        ) as (mock_save, gsp, ip_wrap):
            gsp.side_effect = lambda x, y: y

            self.driver._spawn(self.fake_config)

            mock_save.assert_called_once_with('conf', self.fake_config, 'sock')
            cmd = ['haproxy', '-f', 'conf', '-p', 'pid']
            ip_wrap.assert_has_calls([
                mock.call('sudo', 'qlbaas-pool_id'),
                mock.call().netns.execute(cmd)
            ])

    def test_destroy(self):
        with contextlib.nested(
            mock.patch.object(self.driver, '_get_state_file_path'),
            mock.patch.object(namespace_driver, 'kill_pids_in_file'),
            mock.patch.object(self.driver, '_unplug'),
            mock.patch('quantum.agent.linux.ip_lib.IPWrapper'),
            mock.patch('os.path.isdir'),
            mock.patch('shutil.rmtree')
        ) as (gsp, kill, unplug, ip_wrap, isdir, rmtree):
            gsp.side_effect = lambda x, y: '/pool/' + y

            self.driver.pool_to_port_id['pool_id'] = 'port_id'
            isdir.return_value = True

            self.driver.destroy('pool_id')

            kill.assert_called_once_with(ip_wrap(), '/pool/pid')
            unplug.assert_called_once_with('qlbaas-pool_id', 'port_id')
            isdir.called_once_with('/pool')
            rmtree.assert_called_once_with('/pool')
            ip_wrap.assert_has_calls([
                mock.call('sudo', 'qlbaas-pool_id'),
                mock.call().garbage_collect_namespace()
            ])

    def test_exists(self):
        with contextlib.nested(
            mock.patch.object(self.driver, '_get_state_file_path'),
            mock.patch('quantum.agent.linux.ip_lib.IPWrapper'),
            mock.patch('socket.socket'),
            mock.patch('os.path.exists'),
        ) as (gsp, ip_wrap, socket, path_exists):
            gsp.side_effect = lambda x, y: '/pool/' + y

            ip_wrap.return_value.netns.exists.return_value = True
            path_exists.return_value = True

            self.driver.exists('pool_id')

            ip_wrap.assert_has_calls([
                mock.call('sudo'),
                mock.call().netns.exists('qlbaas-pool_id')
            ])

            self.assertTrue(self.driver.exists('pool_id'))

    def test_get_stats(self):
        raw_stats = ('# pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,'
                     'dreq,dresp,ereq,econ,eresp,wretr,wredis,status,weight,'
                     'act,bck,chkfail,chkdown,lastchg,downtime,qlimit,pid,iid,'
                     'sid,throttle,lbtot,tracked,type,rate,rate_lim,rate_max,'
                     'check_status,check_code,check_duration,hrsp_1xx,'
                     'hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,hrsp_other,hanafail,'
                     'req_rate,req_rate_max,req_tot,cli_abrt,srv_abrt,\n'
                     '8e271901-69ed-403e-a59b-f53cf77ef208,BACKEND,1,2,3,4,0,'
                     '10,7764,2365,0,0,,0,0,0,0,UP,1,1,0,,0,103780,0,,1,2,0,,0'
                     ',,1,0,,0,,,,0,0,0,0,0,0,,,,,0,0,\n\n')
        raw_stats_empty = ('# pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,'
                           'bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,'
                           'status,weight,act,bck,chkfail,chkdown,lastchg,'
                           'downtime,qlimit,pid,iid,sid,throttle,lbtot,'
                           'tracked,type,rate,rate_lim,rate_max,check_status,'
                           'check_code,check_duration,hrsp_1xx,hrsp_2xx,'
                           'hrsp_3xx,hrsp_4xx,hrsp_5xx,hrsp_other,hanafail,'
                           'req_rate,req_rate_max,req_tot,cli_abrt,srv_abrt,'
                           '\n')
        with contextlib.nested(
                mock.patch.object(self.driver, '_get_state_file_path'),
                mock.patch('socket.socket'),
                mock.patch('os.path.exists'),
        ) as (gsp, socket, path_exists):
            gsp.side_effect = lambda x, y: '/pool/' + y
            path_exists.return_value = True
            socket.return_value = socket
            socket.recv.return_value = raw_stats

            exp_stats = {'CONNECTION_ERRORS': '0',
                         'CURRENT_CONNECTIONS': '1',
                         'CURRENT_SESSIONS': '3',
                         'IN_BYTES': '7764',
                         'MAX_CONNECTIONS': '2',
                         'MAX_SESSIONS': '4',
                         'OUT_BYTES': '2365',
                         'RESPONSE_ERRORS': '0',
                         'TOTAL_SESSIONS': '10'}
            stats = self.driver.get_stats('pool_id')
            self.assertEqual(exp_stats, stats)

            socket.recv.return_value = raw_stats_empty
            self.assertEqual({}, self.driver.get_stats('pool_id'))

            path_exists.return_value = False
            socket.reset_mock()
            self.assertEqual({}, self.driver.get_stats('pool_id'))
            self.assertFalse(socket.called)
