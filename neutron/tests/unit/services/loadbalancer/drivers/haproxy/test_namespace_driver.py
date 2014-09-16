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

import contextlib

import mock

from neutron.common import exceptions
from neutron.services.loadbalancer.drivers.haproxy import namespace_driver
from neutron.tests import base


class TestHaproxyNSDriver(base.BaseTestCase):
    def setUp(self):
        super(TestHaproxyNSDriver, self).setUp()

        conf = mock.Mock()
        conf.haproxy.loadbalancer_state_path = '/the/path'
        conf.interface_driver = 'intdriver'
        conf.haproxy.user_group = 'test_group'
        conf.haproxy.send_gratuitous_arp = 3
        conf.AGENT.root_helper = 'sudo_test'
        self.conf = conf
        self.mock_importer = mock.patch.object(namespace_driver,
                                               'importutils').start()

        self.rpc_mock = mock.Mock()
        self.driver = namespace_driver.HaproxyNSDriver(
            conf,
            self.rpc_mock
        )
        self.vif_driver = mock.Mock()
        self.driver.vif_driver = self.vif_driver

        self.fake_config = {
            'pool': {'id': 'pool_id', 'status': 'ACTIVE',
                     'admin_state_up': True},
            'vip': {'id': 'vip_id', 'port': {'id': 'port_id'},
                    'status': 'ACTIVE', 'admin_state_up': True}
        }

    def test_get_name(self):
        self.assertEqual(self.driver.get_name(), namespace_driver.DRIVER_NAME)

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
            mock.patch('neutron.agent.linux.ip_lib.IPWrapper')
        ) as (mock_save, gsp, ip_wrap):
            gsp.side_effect = lambda x, y: y

            self.driver._spawn(self.fake_config)

            mock_save.assert_called_once_with('conf', self.fake_config,
                                              'sock', 'test_group')
            cmd = ['haproxy', '-f', 'conf', '-p', 'pid']
            ip_wrap.assert_has_calls([
                mock.call('sudo_test', 'qlbaas-pool_id'),
                mock.call().netns.execute(cmd)
            ])

    def test_undeploy_instance(self):
        with contextlib.nested(
            mock.patch.object(self.driver, '_get_state_file_path'),
            mock.patch.object(namespace_driver, 'kill_pids_in_file'),
            mock.patch.object(self.driver, '_unplug'),
            mock.patch('neutron.agent.linux.ip_lib.IPWrapper'),
            mock.patch('os.path.isdir'),
            mock.patch('shutil.rmtree')
        ) as (gsp, kill, unplug, ip_wrap, isdir, rmtree):
            gsp.side_effect = lambda x, y: '/pool/' + y

            self.driver.pool_to_port_id['pool_id'] = 'port_id'
            isdir.return_value = True

            self.driver.undeploy_instance('pool_id')

            kill.assert_called_once_with('sudo_test', '/pool/pid')
            unplug.assert_called_once_with('qlbaas-pool_id', 'port_id')
            isdir.assert_called_once_with('/pool')
            rmtree.assert_called_once_with('/pool')
            ip_wrap.assert_has_calls([
                mock.call('sudo_test', 'qlbaas-pool_id'),
                mock.call().garbage_collect_namespace()
            ])

    def test_undeploy_instance_with_ns_cleanup(self):
        with contextlib.nested(
            mock.patch.object(self.driver, '_get_state_file_path'),
            mock.patch.object(self.driver, 'vif_driver'),
            mock.patch.object(namespace_driver, 'kill_pids_in_file'),
            mock.patch('neutron.agent.linux.ip_lib.IPWrapper'),
            mock.patch('os.path.isdir'),
            mock.patch('shutil.rmtree')
        ) as (gsp, vif, kill, ip_wrap, isdir, rmtree):
            device = mock.Mock()
            device_name = 'port_device'
            device.name = device_name
            ip_wrap.return_value.get_devices.return_value = [device]

            self.driver.undeploy_instance('pool_id', cleanup_namespace=True)
            vif.unplug.assert_called_once_with(device_name,
                                               namespace='qlbaas-pool_id')

    def test_remove_orphans(self):
        with contextlib.nested(
            mock.patch.object(self.driver, 'exists'),
            mock.patch.object(self.driver, 'undeploy_instance'),
            mock.patch('os.listdir'),
            mock.patch('os.path.exists')
        ) as (exists, undeploy, listdir, path_exists):
            known = ['known1', 'known2']
            unknown = ['unknown1', 'unknown2']
            listdir.return_value = known + unknown
            exists.side_effect = lambda x: x == 'unknown2'

            self.driver.remove_orphans(known)

            undeploy.assert_called_once_with('unknown2',
                                             cleanup_namespace=True)

    def test_exists(self):
        with contextlib.nested(
            mock.patch.object(self.driver, '_get_state_file_path'),
            mock.patch('neutron.agent.linux.ip_lib.IPWrapper'),
            mock.patch('socket.socket'),
            mock.patch('os.path.exists'),
        ) as (gsp, ip_wrap, socket, path_exists):
            gsp.side_effect = lambda x, y, z: '/pool/' + y

            ip_wrap.return_value.netns.exists.return_value = True
            path_exists.return_value = True

            self.driver.exists('pool_id')

            ip_wrap.assert_has_calls([
                mock.call('sudo_test'),
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
                     ',,1,0,,0,,,,0,0,0,0,0,0,,,,,0,0,\n\n'
                     'a557019b-dc07-4688-9af4-f5cf02bb6d4b,'
                     '32a6c2a3-420a-44c3-955d-86bd2fc6871e,0,0,0,1,,7,1120,'
                     '224,,0,,0,0,0,0,UP,1,1,0,0,1,2623,303,,1,2,1,,7,,2,0,,'
                     '1,L7OK,200,98,0,7,0,0,0,0,0,,,,0,0,\n'
                     'a557019b-dc07-4688-9af4-f5cf02bb6d4b,'
                     'd9aea044-8867-4e80-9875-16fb808fa0f9,0,0,0,2,,12,0,0,,'
                     '0,,0,0,8,4,DOWN,1,1,0,9,2,308,675,,1,2,2,,4,,2,0,,2,'
                     'L4CON,,2999,0,0,0,0,0,0,0,,,,0,0,\n')
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
            gsp.side_effect = lambda x, y, z: '/pool/' + y
            path_exists.return_value = True
            socket.return_value = socket
            socket.recv.return_value = raw_stats

            exp_stats = {'connection_errors': '0',
                         'active_connections': '3',
                         'current_sessions': '3',
                         'bytes_in': '7764',
                         'max_connections': '4',
                         'max_sessions': '4',
                         'bytes_out': '2365',
                         'response_errors': '0',
                         'total_sessions': '10',
                         'total_connections': '10',
                         'members': {
                             '32a6c2a3-420a-44c3-955d-86bd2fc6871e': {
                                 'status': 'ACTIVE',
                                 'health': 'L7OK',
                                 'failed_checks': '0'
                             },
                             'd9aea044-8867-4e80-9875-16fb808fa0f9': {
                                 'status': 'INACTIVE',
                                 'health': 'L4CON',
                                 'failed_checks': '9'
                             }
                         }
                         }
            stats = self.driver.get_stats('pool_id')
            self.assertEqual(exp_stats, stats)

            socket.recv.return_value = raw_stats_empty
            self.assertEqual({'members': {}}, self.driver.get_stats('pool_id'))

            path_exists.return_value = False
            socket.reset_mock()
            self.assertEqual({}, self.driver.get_stats('pool_id'))
            self.assertFalse(socket.called)

    def test_plug(self):
        test_port = {'id': 'port_id',
                     'network_id': 'net_id',
                     'mac_address': 'mac_addr',
                     'fixed_ips': [{'ip_address': '10.0.0.2',
                                    'subnet': {'cidr': '10.0.0.0/24',
                                               'gateway_ip': '10.0.0.1'}}]}
        with contextlib.nested(
                mock.patch('neutron.agent.linux.ip_lib.device_exists'),
                mock.patch('netaddr.IPNetwork'),
                mock.patch('neutron.agent.linux.ip_lib.IPWrapper'),
        ) as (dev_exists, ip_net, ip_wrap):
            self.vif_driver.get_device_name.return_value = 'test_interface'
            dev_exists.return_value = False
            ip_net.return_value = ip_net
            ip_net.prefixlen = 24

            self.driver._plug('test_ns', test_port)
            self.rpc_mock.plug_vip_port.assert_called_once_with(
                test_port['id'])
            self.assertTrue(dev_exists.called)
            self.vif_driver.plug.assert_called_once_with('net_id', 'port_id',
                                                         'test_interface',
                                                         'mac_addr',
                                                         namespace='test_ns')
            self.vif_driver.init_l3.assert_called_once_with('test_interface',
                                                            ['10.0.0.2/24'],
                                                            namespace=
                                                            'test_ns')
            cmd = ['route', 'add', 'default', 'gw', '10.0.0.1']
            cmd_arping = ['arping', '-U', '-I',
                          'test_interface', '-c',
                          self.conf.haproxy.send_gratuitous_arp, '10.0.0.2']
            ip_wrap.assert_has_calls([
                mock.call('sudo_test', namespace='test_ns'),
                mock.call().netns.execute(cmd, check_exit_code=False),
                mock.call().netns.execute(cmd_arping, check_exit_code=False),
            ])

            dev_exists.return_value = True
            self.assertRaises(exceptions.PreexistingDeviceFailure,
                              self.driver._plug, 'test_ns', test_port, False)

    def test_plug_not_send_gratuitous_arp(self):
        self.conf.haproxy.send_gratuitous_arp = 0
        test_port = {'id': 'port_id',
                     'network_id': 'net_id',
                     'mac_address': 'mac_addr',
                     'fixed_ips': [{'ip_address': '10.0.0.2',
                                    'subnet': {'cidr': '10.0.0.0/24',
                                               'gateway_ip': '10.0.0.1'}}]}
        with contextlib.nested(
                mock.patch('neutron.agent.linux.ip_lib.device_exists'),
                mock.patch('netaddr.IPNetwork'),
                mock.patch('neutron.agent.linux.ip_lib.IPWrapper'),
        ) as (dev_exists, ip_net, ip_wrap):
            self.vif_driver.get_device_name.return_value = 'test_interface'
            dev_exists.return_value = False
            ip_net.return_value = ip_net
            ip_net.prefixlen = 24

            self.driver._plug('test_ns', test_port)
            cmd = ['route', 'add', 'default', 'gw', '10.0.0.1']
            expected = [
                mock.call('sudo_test', namespace='test_ns'),
                mock.call().netns.execute(cmd, check_exit_code=False)]
            self.assertEqual(expected, ip_wrap.mock_calls)

    def test_plug_no_gw(self):
        test_port = {'id': 'port_id',
                     'network_id': 'net_id',
                     'mac_address': 'mac_addr',
                     'fixed_ips': [{'ip_address': '10.0.0.2',
                                    'subnet': {'cidr': '10.0.0.0/24'}}]}
        with contextlib.nested(
                mock.patch('neutron.agent.linux.ip_lib.device_exists'),
                mock.patch('netaddr.IPNetwork'),
                mock.patch('neutron.agent.linux.ip_lib.IPWrapper'),
        ) as (dev_exists, ip_net, ip_wrap):
            self.vif_driver.get_device_name.return_value = 'test_interface'
            dev_exists.return_value = False
            ip_net.return_value = ip_net
            ip_net.prefixlen = 24

            self.driver._plug('test_ns', test_port)
            self.rpc_mock.plug_vip_port.assert_called_once_with(
                test_port['id'])
            self.assertTrue(dev_exists.called)
            self.vif_driver.plug.assert_called_once_with('net_id', 'port_id',
                                                         'test_interface',
                                                         'mac_addr',
                                                         namespace='test_ns')
            self.vif_driver.init_l3.assert_called_once_with('test_interface',
                                                            ['10.0.0.2/24'],
                                                            namespace=
                                                            'test_ns')
            self.assertFalse(ip_wrap.called)
            dev_exists.return_value = True
            self.assertRaises(exceptions.PreexistingDeviceFailure,
                              self.driver._plug, 'test_ns', test_port, False)

    def test_plug_gw_in_host_routes(self):
        test_port = {'id': 'port_id',
                     'network_id': 'net_id',
                     'mac_address': 'mac_addr',
                     'fixed_ips': [{'ip_address': '10.0.0.2',
                                    'subnet': {'cidr': '10.0.0.0/24',
                                               'host_routes':
                                               [{'destination': '0.0.0.0/0',
                                                 'nexthop': '10.0.0.1'}]}}]}
        with contextlib.nested(
                mock.patch('neutron.agent.linux.ip_lib.device_exists'),
                mock.patch('netaddr.IPNetwork'),
                mock.patch('neutron.agent.linux.ip_lib.IPWrapper'),
        ) as (dev_exists, ip_net, ip_wrap):
            self.vif_driver.get_device_name.return_value = 'test_interface'
            dev_exists.return_value = False
            ip_net.return_value = ip_net
            ip_net.prefixlen = 24

            self.driver._plug('test_ns', test_port)
            self.rpc_mock.plug_vip_port.assert_called_once_with(
                test_port['id'])
            self.assertTrue(dev_exists.called)
            self.vif_driver.plug.assert_called_once_with('net_id', 'port_id',
                                                         'test_interface',
                                                         'mac_addr',
                                                         namespace='test_ns')
            self.vif_driver.init_l3.assert_called_once_with('test_interface',
                                                            ['10.0.0.2/24'],
                                                            namespace=
                                                            'test_ns')
            cmd = ['route', 'add', 'default', 'gw', '10.0.0.1']
            ip_wrap.assert_has_calls([
                mock.call('sudo_test', namespace='test_ns'),
                mock.call().netns.execute(cmd, check_exit_code=False),
            ])

    def test_unplug(self):
        self.vif_driver.get_device_name.return_value = 'test_interface'

        self.driver._unplug('test_ns', 'port_id')
        self.rpc_mock.unplug_vip_port.assert_called_once_with('port_id')
        self.vif_driver.unplug('test_interface', namespace='test_ns')

    def test_kill_pids_in_file(self):
        with contextlib.nested(
            mock.patch('os.path.exists'),
            mock.patch('__builtin__.open'),
            mock.patch('neutron.agent.linux.utils.execute'),
            mock.patch.object(namespace_driver.LOG, 'exception'),
        ) as (path_exists, mock_open, mock_execute, mock_log):
            file_mock = mock.MagicMock()
            mock_open.return_value = file_mock
            file_mock.__enter__.return_value = file_mock
            file_mock.__iter__.return_value = iter(['123'])

            path_exists.return_value = False
            namespace_driver.kill_pids_in_file('sudo_test', 'test_path')
            path_exists.assert_called_once_with('test_path')
            self.assertFalse(mock_open.called)
            self.assertFalse(mock_execute.called)

            path_exists.return_value = True
            mock_execute.side_effect = RuntimeError
            namespace_driver.kill_pids_in_file('sudo_test', 'test_path')
            self.assertTrue(mock_log.called)
            mock_execute.assert_called_once_with(
                ['kill', '-9', '123'], 'sudo_test')

    def test_get_state_file_path(self):
        with mock.patch('os.makedirs') as mkdir:
            path = self.driver._get_state_file_path('pool_id', 'conf')
            self.assertEqual('/the/path/pool_id/conf', path)
            mkdir.assert_called_once_with('/the/path/pool_id', 0o755)

    def test_deploy_instance(self):
        with mock.patch.object(self.driver, 'exists') as exists:
            with mock.patch.object(self.driver, 'update') as update:
                self.driver.deploy_instance(self.fake_config)
                exists.assert_called_once_with(self.fake_config['pool']['id'])
                update.assert_called_once_with(self.fake_config)

    def test_deploy_instance_non_existing(self):
        with mock.patch.object(self.driver, 'exists') as exists:
            with mock.patch.object(self.driver, 'create') as create:
                exists.return_value = False
                self.driver.deploy_instance(self.fake_config)
                exists.assert_called_once_with(self.fake_config['pool']['id'])
                create.assert_called_once_with(self.fake_config)

    def test_deploy_instance_vip_status_non_active(self):
        with mock.patch.object(self.driver, 'exists') as exists:
            self.fake_config['vip']['status'] = 'NON_ACTIVE'
            self.driver.deploy_instance(self.fake_config)
            self.assertFalse(exists.called)

    def test_deploy_instance_vip_admin_state_down(self):
        with mock.patch.object(self.driver, 'exists') as exists:
            self.fake_config['vip']['admin_state_up'] = False
            self.driver.deploy_instance(self.fake_config)
            self.assertFalse(exists.called)

    def test_deploy_instance_no_vip(self):
        with mock.patch.object(self.driver, 'exists') as exists:
            del self.fake_config['vip']
            self.driver.deploy_instance(self.fake_config)
            self.assertFalse(exists.called)

    def test_deploy_instance_pool_status_non_active(self):
        with mock.patch.object(self.driver, 'exists') as exists:
            self.fake_config['pool']['status'] = 'NON_ACTIVE'
            self.driver.deploy_instance(self.fake_config)
            self.assertFalse(exists.called)

    def test_deploy_instance_pool_admin_state_down(self):
        with mock.patch.object(self.driver, 'exists') as exists:
            self.fake_config['pool']['admin_state_up'] = False
            self.driver.deploy_instance(self.fake_config)
            self.assertFalse(exists.called)

    def test_refresh_device(self):
        with mock.patch.object(self.driver, 'deploy_instance') as deploy:
            pool_id = 'pool_id1'
            self.driver._refresh_device(pool_id)
            self.rpc_mock.get_logical_device.assert_called_once_with(pool_id)
            deploy.assert_called_once_with(
                self.rpc_mock.get_logical_device.return_value)

    def test_create_vip(self):
        with mock.patch.object(self.driver, '_refresh_device') as refresh:
            self.driver.create_vip({'pool_id': '1'})
            refresh.assert_called_once_with('1')

    def test_update_vip(self):
        with mock.patch.object(self.driver, '_refresh_device') as refresh:
            self.driver.update_vip({}, {'pool_id': '1'})
            refresh.assert_called_once_with('1')

    def test_delete_vip(self):
        with mock.patch.object(self.driver, 'undeploy_instance') as undeploy:
            self.driver.delete_vip({'pool_id': '1'})
            undeploy.assert_called_once_with('1')

    def test_create_pool(self):
        with mock.patch.object(self.driver, '_refresh_device') as refresh:
            self.driver.create_pool({'id': '1'})
            self.assertFalse(refresh.called)

    def test_update_pool(self):
        with mock.patch.object(self.driver, '_refresh_device') as refresh:
            self.driver.update_pool({}, {'id': '1'})
            refresh.assert_called_once_with('1')

    def test_delete_pool_existing(self):
        with mock.patch.object(self.driver, 'undeploy_instance') as undeploy:
            with mock.patch.object(self.driver, 'exists') as exists:
                exists.return_value = True
                self.driver.delete_pool({'id': '1'})
                undeploy.assert_called_once_with('1')

    def test_delete_pool_non_existing(self):
        with mock.patch.object(self.driver, 'undeploy_instance') as undeploy:
            with mock.patch.object(self.driver, 'exists') as exists:
                exists.return_value = False
                self.driver.delete_pool({'id': '1'})
                self.assertFalse(undeploy.called)

    def test_create_member(self):
        with mock.patch.object(self.driver, '_refresh_device') as refresh:
            self.driver.create_member({'pool_id': '1'})
            refresh.assert_called_once_with('1')

    def test_update_member(self):
        with mock.patch.object(self.driver, '_refresh_device') as refresh:
            self.driver.update_member({}, {'pool_id': '1'})
            refresh.assert_called_once_with('1')

    def test_delete_member(self):
        with mock.patch.object(self.driver, '_refresh_device') as refresh:
            self.driver.delete_member({'pool_id': '1'})
            refresh.assert_called_once_with('1')

    def test_create_pool_health_monitor(self):
        with mock.patch.object(self.driver, '_refresh_device') as refresh:
            self.driver.create_pool_health_monitor('', '1')
            refresh.assert_called_once_with('1')

    def test_update_pool_health_monitor(self):
        with mock.patch.object(self.driver, '_refresh_device') as refresh:
            self.driver.update_pool_health_monitor('', '', '1')
            refresh.assert_called_once_with('1')

    def test_delete_pool_health_monitor(self):
        with mock.patch.object(self.driver, '_refresh_device') as refresh:
            self.driver.delete_pool_health_monitor('', '1')
            refresh.assert_called_once_with('1')
