# Copyright 2012 OpenStack Foundation
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

import collections
import copy
import sys
import uuid

import eventlet
import mock
from oslo_config import cfg
import oslo_messaging
import testtools

from neutron.agent.common import config
from neutron.agent.dhcp import agent as dhcp_agent
from neutron.agent.dhcp import config as dhcp_config
from neutron.agent import dhcp_agent as entry
from neutron.agent.linux import dhcp
from neutron.agent.linux import interface
from neutron.common import config as common_config
from neutron.common import constants as const
from neutron.common import exceptions
from neutron.common import utils
from neutron import context
from neutron.tests import base


HOSTNAME = 'hostname'
dev_man = dhcp.DeviceManager
rpc_api = dhcp_agent.DhcpPluginApi
DEVICE_MANAGER = '%s.%s' % (dev_man.__module__, dev_man.__name__)
DHCP_PLUGIN = '%s.%s' % (rpc_api.__module__, rpc_api.__name__)


fake_tenant_id = 'aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa'
fake_subnet1_allocation_pools = dhcp.DictModel(dict(id='', start='172.9.9.2',
                                               end='172.9.9.254'))
fake_subnet1 = dhcp.DictModel(dict(id='bbbbbbbb-bbbb-bbbb-bbbbbbbbbbbb',
                              network_id='12345678-1234-5678-1234567890ab',
                              cidr='172.9.9.0/24', enable_dhcp=True, name='',
                              tenant_id=fake_tenant_id,
                              gateway_ip='172.9.9.1', host_routes=[],
                              dns_nameservers=[], ip_version=4,
                              ipv6_ra_mode=None, ipv6_address_mode=None,
                              allocation_pools=fake_subnet1_allocation_pools))

fake_subnet2_allocation_pools = dhcp.DictModel(dict(id='', start='172.9.8.2',
                                               end='172.9.8.254'))
fake_subnet2 = dhcp.DictModel(dict(id='dddddddd-dddd-dddd-dddddddddddd',
                              network_id='12345678-1234-5678-1234567890ab',
                              cidr='172.9.8.0/24', enable_dhcp=False, name='',
                              tenant_id=fake_tenant_id, gateway_ip='172.9.8.1',
                              host_routes=[], dns_nameservers=[], ip_version=4,
                              allocation_pools=fake_subnet2_allocation_pools))

fake_subnet3 = dhcp.DictModel(dict(id='bbbbbbbb-1111-2222-bbbbbbbbbbbb',
                              network_id='12345678-1234-5678-1234567890ab',
                              cidr='192.168.1.1/24', enable_dhcp=True))

fake_ipv6_subnet = dhcp.DictModel(dict(id='bbbbbbbb-1111-2222-bbbbbbbbbbbb',
                              network_id='12345678-1234-5678-1234567890ab',
                              cidr='2001:0db8::0/64', enable_dhcp=True,
                              tenant_id=fake_tenant_id,
                              gateway_ip='2001:0db8::1', ip_version=6,
                              ipv6_ra_mode='slaac', ipv6_address_mode=None))

fake_meta_subnet = dhcp.DictModel(dict(id='bbbbbbbb-1111-2222-bbbbbbbbbbbb',
                                  network_id='12345678-1234-5678-1234567890ab',
                                  cidr='169.254.169.252/30',
                                  gateway_ip='169.254.169.253',
                                  enable_dhcp=True))

fake_fixed_ip1 = dhcp.DictModel(dict(id='', subnet_id=fake_subnet1.id,
                                ip_address='172.9.9.9'))
fake_fixed_ip2 = dhcp.DictModel(dict(id='', subnet_id=fake_subnet1.id,
                                ip_address='172.9.9.10'))
fake_fixed_ipv6 = dhcp.DictModel(dict(id='', subnet_id=fake_ipv6_subnet.id,
                                 ip_address='2001:db8::a8bb:ccff:fedd:ee99'))
fake_meta_fixed_ip = dhcp.DictModel(dict(id='', subnet=fake_meta_subnet,
                                    ip_address='169.254.169.254'))
fake_allocation_pool_subnet1 = dhcp.DictModel(dict(id='', start='172.9.9.2',
                                              end='172.9.9.254'))

fake_port1 = dhcp.DictModel(dict(id='12345678-1234-aaaa-1234567890ab',
                            device_id='dhcp-12345678-1234-aaaa-1234567890ab',
                            device_owner='',
                            allocation_pools=fake_subnet1_allocation_pools,
                            mac_address='aa:bb:cc:dd:ee:ff',
                            network_id='12345678-1234-5678-1234567890ab',
                            fixed_ips=[fake_fixed_ip1]))

fake_port2 = dhcp.DictModel(dict(id='12345678-1234-aaaa-123456789000',
                            device_id='dhcp-12345678-1234-aaaa-123456789000',
                            device_owner='',
                            mac_address='aa:bb:cc:dd:ee:99',
                            network_id='12345678-1234-5678-1234567890ab',
                            fixed_ips=[fake_fixed_ip2]))

fake_ipv6_port = dhcp.DictModel(dict(id='12345678-1234-aaaa-123456789000',
                                device_owner='',
                                mac_address='aa:bb:cc:dd:ee:99',
                                network_id='12345678-1234-5678-1234567890ab',
                                fixed_ips=[fake_fixed_ipv6]))

fake_meta_port = dhcp.DictModel(dict(id='12345678-1234-aaaa-1234567890ab',
                                mac_address='aa:bb:cc:dd:ee:ff',
                                network_id='12345678-1234-5678-1234567890ab',
                                device_owner=const.DEVICE_OWNER_ROUTER_INTF,
                                device_id='forzanapoli',
                                fixed_ips=[fake_meta_fixed_ip]))

fake_meta_dvr_port = dhcp.DictModel(fake_meta_port.copy())
fake_meta_dvr_port.device_owner = const.DEVICE_OWNER_DVR_INTERFACE

fake_dist_port = dhcp.DictModel(dict(id='12345678-1234-aaaa-1234567890ab',
                                mac_address='aa:bb:cc:dd:ee:ff',
                                network_id='12345678-1234-5678-1234567890ab',
                                device_owner=const.DEVICE_OWNER_DVR_INTERFACE,
                                device_id='forzanapoli',
                                fixed_ips=[fake_meta_fixed_ip]))

FAKE_NETWORK_UUID = '12345678-1234-5678-1234567890ab'
FAKE_NETWORK_DHCP_NS = "qdhcp-%s" % FAKE_NETWORK_UUID

fake_network = dhcp.NetModel(True, dict(id=FAKE_NETWORK_UUID,
                             tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa',
                             admin_state_up=True,
                             subnets=[fake_subnet1, fake_subnet2],
                             ports=[fake_port1]))

fake_network_ipv6 = dhcp.NetModel(True, dict(
                             id='12345678-1234-5678-1234567890ab',
                             tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa',
                             admin_state_up=True,
                             subnets=[fake_ipv6_subnet],
                             ports=[fake_ipv6_port]))

fake_network_ipv6_ipv4 = dhcp.NetModel(True, dict(
                             id='12345678-1234-5678-1234567890ab',
                             tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa',
                             admin_state_up=True,
                             subnets=[fake_ipv6_subnet, fake_subnet1],
                             ports=[fake_port1]))

isolated_network = dhcp.NetModel(
    True, dict(
        id='12345678-1234-5678-1234567890ab',
        tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa',
        admin_state_up=True,
        subnets=[fake_subnet1],
        ports=[fake_port1]))

nonisolated_dist_network = dhcp.NetModel(
    True, dict(
        id='12345678-1234-5678-1234567890ab',
        tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa',
        admin_state_up=True,
        subnets=[fake_subnet1],
        ports=[fake_port1, fake_port2]))

empty_network = dhcp.NetModel(
    True, dict(
        id='12345678-1234-5678-1234567890ab',
        tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa',
        admin_state_up=True,
        subnets=[fake_subnet1],
        ports=[]))

fake_meta_network = dhcp.NetModel(
    True, dict(id='12345678-1234-5678-1234567890ab',
               tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa',
               admin_state_up=True,
               subnets=[fake_meta_subnet],
               ports=[fake_meta_port]))

fake_meta_dvr_network = dhcp.NetModel(True, fake_meta_network.copy())
fake_meta_dvr_network.ports = [fake_meta_dvr_port]

fake_dist_network = dhcp.NetModel(
    True, dict(id='12345678-1234-5678-1234567890ab',
               tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa',
               admin_state_up=True,
               subnets=[fake_meta_subnet],
               ports=[fake_meta_port, fake_dist_port]))

fake_down_network = dhcp.NetModel(
    True, dict(id='12345678-dddd-dddd-1234567890ab',
               tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa',
               admin_state_up=False,
               subnets=[],
               ports=[]))


class TestDhcpAgent(base.BaseTestCase):
    def setUp(self):
        super(TestDhcpAgent, self).setUp()
        entry.register_options()
        cfg.CONF.set_override('interface_driver',
                              'neutron.agent.linux.interface.NullDriver')
        # disable setting up periodic state reporting
        cfg.CONF.set_override('report_interval', 0, 'AGENT')

        self.driver_cls_p = mock.patch(
            'neutron.agent.dhcp.agent.importutils.import_class')
        self.driver = mock.Mock(name='driver')
        self.driver.existing_dhcp_networks.return_value = []
        self.driver_cls = self.driver_cls_p.start()
        self.driver_cls.return_value = self.driver
        self.mock_makedirs_p = mock.patch("os.makedirs")
        self.mock_makedirs = self.mock_makedirs_p.start()

    def test_init_host(self):
        dhcp = dhcp_agent.DhcpAgent(HOSTNAME)
        with mock.patch.object(dhcp, 'sync_state') as sync_state:
            dhcp.init_host()
            sync_state.assert_called_once_with()

    def test_dhcp_agent_manager(self):
        state_rpc_str = 'neutron.agent.rpc.PluginReportStateAPI'
        # sync_state is needed for this test
        cfg.CONF.set_override('report_interval', 1, 'AGENT')
        with mock.patch.object(dhcp_agent.DhcpAgentWithStateReport,
                               'sync_state',
                               autospec=True) as mock_sync_state:
            with mock.patch.object(dhcp_agent.DhcpAgentWithStateReport,
                                   'periodic_resync',
                                   autospec=True) as mock_periodic_resync:
                with mock.patch(state_rpc_str) as state_rpc:
                    with mock.patch.object(sys, 'argv') as sys_argv:
                        sys_argv.return_value = [
                            'dhcp', '--config-file',
                            base.etcdir('neutron.conf')]
                        cfg.CONF.register_opts(dhcp_config.DHCP_AGENT_OPTS)
                        config.register_interface_driver_opts_helper(cfg.CONF)
                        config.register_agent_state_opts_helper(cfg.CONF)
                        cfg.CONF.register_opts(interface.OPTS)
                        common_config.init(sys.argv[1:])
                        agent_mgr = dhcp_agent.DhcpAgentWithStateReport(
                            'testhost')
                        eventlet.greenthread.sleep(1)
                        agent_mgr.after_start()
                        mock_sync_state.assert_called_once_with(agent_mgr)
                        mock_periodic_resync.assert_called_once_with(agent_mgr)
                        state_rpc.assert_has_calls(
                            [mock.call(mock.ANY),
                             mock.call().report_state(mock.ANY, mock.ANY,
                                                      mock.ANY)])

    def test_dhcp_agent_main_agent_manager(self):
        logging_str = 'neutron.agent.common.config.setup_logging'
        launcher_str = 'oslo_service.service.ServiceLauncher'
        with mock.patch(logging_str):
            with mock.patch.object(sys, 'argv') as sys_argv:
                with mock.patch(launcher_str) as launcher:
                    sys_argv.return_value = ['dhcp', '--config-file',
                                             base.etcdir('neutron.conf')]
                    entry.main()
                    launcher.assert_has_calls(
                        [mock.call(cfg.CONF),
                         mock.call().launch_service(mock.ANY),
                         mock.call().wait()])

    def test_run_completes_single_pass(self):
        with mock.patch(DEVICE_MANAGER):
            dhcp = dhcp_agent.DhcpAgent(HOSTNAME)
            attrs_to_mock = dict(
                [(a, mock.DEFAULT) for a in
                 ['sync_state', 'periodic_resync']])
            with mock.patch.multiple(dhcp, **attrs_to_mock) as mocks:
                dhcp.run()
                mocks['sync_state'].assert_called_once_with()
                mocks['periodic_resync'].assert_called_once_with()

    def test_call_driver(self):
        network = mock.Mock()
        network.id = '1'
        dhcp = dhcp_agent.DhcpAgent(cfg.CONF)
        self.assertTrue(dhcp.call_driver('foo', network))
        self.driver.assert_called_once_with(cfg.CONF,
                                            mock.ANY,
                                            mock.ANY,
                                            mock.ANY,
                                            mock.ANY)

    def _test_call_driver_failure(self, exc=None,
                                  trace_level='exception', expected_sync=True):
        network = mock.Mock()
        network.id = '1'
        self.driver.return_value.foo.side_effect = exc or Exception
        with mock.patch.object(dhcp_agent.LOG, trace_level) as log:
            dhcp = dhcp_agent.DhcpAgent(HOSTNAME)
            with mock.patch.object(dhcp,
                                   'schedule_resync') as schedule_resync:
                self.assertIsNone(dhcp.call_driver('foo', network))
                self.driver.assert_called_once_with(cfg.CONF,
                                                    mock.ANY,
                                                    mock.ANY,
                                                    mock.ANY,
                                                    mock.ANY)
                self.assertEqual(log.call_count, 1)
                self.assertEqual(expected_sync, schedule_resync.called)

    def test_call_driver_ip_address_generation_failure(self):
        error = oslo_messaging.RemoteError(
            exc_type='IpAddressGenerationFailure')
        self._test_call_driver_failure(exc=error, expected_sync=False)

    def test_call_driver_failure(self):
        self._test_call_driver_failure()

    def test_call_driver_remote_error_net_not_found(self):
        self._test_call_driver_failure(
            exc=oslo_messaging.RemoteError(exc_type='NetworkNotFound'),
            trace_level='warning')

    def test_call_driver_network_not_found(self):
        self._test_call_driver_failure(
            exc=exceptions.NetworkNotFound(net_id='1'),
            trace_level='warning')

    def test_call_driver_conflict(self):
        self._test_call_driver_failure(
            exc=exceptions.Conflict(),
            trace_level='warning',
            expected_sync=False)

    def _test_sync_state_helper(self, known_net_ids, active_net_ids):
        active_networks = set(mock.Mock(id=netid) for netid in active_net_ids)

        with mock.patch(DHCP_PLUGIN) as plug:
            mock_plugin = mock.Mock()
            mock_plugin.get_active_networks_info.return_value = active_networks
            plug.return_value = mock_plugin

            dhcp = dhcp_agent.DhcpAgent(HOSTNAME)

            attrs_to_mock = dict([(a, mock.DEFAULT)
                                 for a in ['disable_dhcp_helper', 'cache',
                                           'safe_configure_dhcp_for_network']])

            with mock.patch.multiple(dhcp, **attrs_to_mock) as mocks:
                mocks['cache'].get_network_ids.return_value = known_net_ids
                dhcp.sync_state()

                diff = set(known_net_ids) - set(active_net_ids)
                exp_disable = [mock.call(net_id) for net_id in diff]
                mocks['cache'].assert_has_calls([mock.call.get_network_ids()])
                mocks['disable_dhcp_helper'].assert_has_calls(exp_disable)

    def test_sync_state_initial(self):
        self._test_sync_state_helper([], ['a'])

    def test_sync_state_same(self):
        self._test_sync_state_helper(['a'], ['a'])

    def test_sync_state_disabled_net(self):
        self._test_sync_state_helper(['b'], ['a'])

    def test_sync_state_waitall(self):
        with mock.patch.object(dhcp_agent.eventlet.GreenPool, 'waitall') as w:
            active_net_ids = ['1', '2', '3', '4', '5']
            known_net_ids = ['1', '2', '3', '4', '5']
            self._test_sync_state_helper(known_net_ids, active_net_ids)
            w.assert_called_once_with()

    def test_sync_state_plugin_error(self):
        with mock.patch(DHCP_PLUGIN) as plug:
            mock_plugin = mock.Mock()
            mock_plugin.get_active_networks_info.side_effect = Exception
            plug.return_value = mock_plugin

            with mock.patch.object(dhcp_agent.LOG, 'exception') as log:
                dhcp = dhcp_agent.DhcpAgent(HOSTNAME)
                with mock.patch.object(dhcp,
                                       'schedule_resync') as schedule_resync:
                    dhcp.sync_state()

                    self.assertTrue(log.called)
                    self.assertTrue(schedule_resync.called)

    def test_periodic_resync(self):
        dhcp = dhcp_agent.DhcpAgent(HOSTNAME)
        with mock.patch.object(dhcp_agent.eventlet, 'spawn') as spawn:
            dhcp.periodic_resync()
            spawn.assert_called_once_with(dhcp._periodic_resync_helper)

    def test_periodic_resync_helper(self):
        with mock.patch.object(dhcp_agent.eventlet, 'sleep') as sleep:
            dhcp = dhcp_agent.DhcpAgent(HOSTNAME)
            resync_reasons = collections.OrderedDict(
                (('a', 'reason1'), ('b', 'reason2')))
            dhcp.needs_resync_reasons = resync_reasons
            with mock.patch.object(dhcp, 'sync_state') as sync_state:
                sync_state.side_effect = RuntimeError
                with testtools.ExpectedException(RuntimeError):
                    dhcp._periodic_resync_helper()
                sync_state.assert_called_once_with(resync_reasons.keys())
                sleep.assert_called_once_with(dhcp.conf.resync_interval)
                self.assertEqual(len(dhcp.needs_resync_reasons), 0)

    def test_populate_cache_on_start_without_active_networks_support(self):
        # emul dhcp driver that doesn't support retrieving of active networks
        self.driver.existing_dhcp_networks.side_effect = NotImplementedError

        with mock.patch.object(dhcp_agent.LOG, 'debug') as log:
            dhcp = dhcp_agent.DhcpAgent(HOSTNAME)

            self.driver.existing_dhcp_networks.assert_called_once_with(
                dhcp.conf,
            )

            self.assertFalse(dhcp.cache.get_network_ids())
            self.assertTrue(log.called)

    def test_populate_cache_on_start(self):
        networks = ['aaa', 'bbb']
        self.driver.existing_dhcp_networks.return_value = networks

        dhcp = dhcp_agent.DhcpAgent(HOSTNAME)

        self.driver.existing_dhcp_networks.assert_called_once_with(
            dhcp.conf,
        )

        self.assertEqual(set(networks), set(dhcp.cache.get_network_ids()))

    def test_none_interface_driver(self):
        cfg.CONF.set_override('interface_driver', None)
        self.assertRaises(SystemExit, dhcp.DeviceManager,
                          cfg.CONF, None)

    def test_nonexistent_interface_driver(self):
        # Temporarily turn off mock, so could use the real import_class
        # to import interface_driver.
        self.driver_cls_p.stop()
        self.addCleanup(self.driver_cls_p.start)
        cfg.CONF.set_override('interface_driver', 'foo.bar')
        self.assertRaises(SystemExit, dhcp.DeviceManager,
                          cfg.CONF, None)


class TestLogArgs(base.BaseTestCase):

    def test_log_args_without_log_dir_and_file(self):
        conf_dict = {'debug': True,
                     'verbose': False,
                     'log_dir': None,
                     'log_file': None,
                     'use_syslog': True,
                     'syslog_log_facility': 'LOG_USER'}
        conf = dhcp.DictModel(conf_dict)
        expected_args = ['--debug',
                         '--use-syslog',
                         '--syslog-log-facility=LOG_USER']
        args = config.get_log_args(conf, 'log_file_name')
        self.assertEqual(expected_args, args)

    def test_log_args_without_log_file(self):
        conf_dict = {'debug': True,
                     'verbose': True,
                     'log_dir': '/etc/tests',
                     'log_file': None,
                     'use_syslog': False,
                     'syslog_log_facility': 'LOG_USER'}
        conf = dhcp.DictModel(conf_dict)
        expected_args = ['--debug',
                         '--verbose',
                         '--log-file=log_file_name',
                         '--log-dir=/etc/tests']
        args = config.get_log_args(conf, 'log_file_name')
        self.assertEqual(expected_args, args)

    def test_log_args_with_log_dir_and_file(self):
        conf_dict = {'debug': True,
                     'verbose': False,
                     'log_dir': '/etc/tests',
                     'log_file': 'tests/filelog',
                     'use_syslog': False,
                     'syslog_log_facility': 'LOG_USER'}
        conf = dhcp.DictModel(conf_dict)
        expected_args = ['--debug',
                         '--log-file=log_file_name',
                         '--log-dir=/etc/tests/tests']
        args = config.get_log_args(conf, 'log_file_name')
        self.assertEqual(expected_args, args)

    def test_log_args_without_log_dir(self):
        conf_dict = {'debug': True,
                     'verbose': False,
                     'log_file': 'tests/filelog',
                     'log_dir': None,
                     'use_syslog': False,
                     'syslog_log_facility': 'LOG_USER'}
        conf = dhcp.DictModel(conf_dict)
        expected_args = ['--debug',
                         '--log-file=log_file_name',
                         '--log-dir=tests']
        args = config.get_log_args(conf, 'log_file_name')
        self.assertEqual(expected_args, args)

    def test_log_args_with_filelog_and_syslog(self):
        conf_dict = {'debug': True,
                     'verbose': True,
                     'log_file': 'tests/filelog',
                     'log_dir': '/etc/tests',
                     'use_syslog': True,
                     'syslog_log_facility': 'LOG_USER'}
        conf = dhcp.DictModel(conf_dict)
        expected_args = ['--debug',
                         '--verbose',
                         '--log-file=log_file_name',
                         '--log-dir=/etc/tests/tests']
        args = config.get_log_args(conf, 'log_file_name')
        self.assertEqual(expected_args, args)


class TestDhcpAgentEventHandler(base.BaseTestCase):
    def setUp(self):
        super(TestDhcpAgentEventHandler, self).setUp()
        config.register_interface_driver_opts_helper(cfg.CONF)
        cfg.CONF.set_override('interface_driver',
                              'neutron.agent.linux.interface.NullDriver')
        entry.register_options()  # register all dhcp cfg options

        self.plugin_p = mock.patch(DHCP_PLUGIN)
        plugin_cls = self.plugin_p.start()
        self.plugin = mock.Mock()
        plugin_cls.return_value = self.plugin

        self.cache_p = mock.patch('neutron.agent.dhcp.agent.NetworkCache')
        cache_cls = self.cache_p.start()
        self.cache = mock.Mock()
        cache_cls.return_value = self.cache
        self.mock_makedirs_p = mock.patch("os.makedirs")
        self.mock_makedirs = self.mock_makedirs_p.start()
        self.mock_init_p = mock.patch('neutron.agent.dhcp.agent.'
                                      'DhcpAgent._populate_networks_cache')
        self.mock_init = self.mock_init_p.start()
        self.dhcp = dhcp_agent.DhcpAgent(HOSTNAME)
        self.call_driver_p = mock.patch.object(self.dhcp, 'call_driver')
        self.call_driver = self.call_driver_p.start()
        self.schedule_resync_p = mock.patch.object(self.dhcp,
                                                   'schedule_resync')
        self.schedule_resync = self.schedule_resync_p.start()
        self.external_process_p = mock.patch(
            'neutron.agent.linux.external_process.ProcessManager'
        )
        self.external_process = self.external_process_p.start()

    def _process_manager_constructor_call(self, ns=FAKE_NETWORK_DHCP_NS):
        return mock.call(conf=cfg.CONF,
                         uuid=FAKE_NETWORK_UUID,
                         namespace=ns,
                         default_cmd_callback=mock.ANY)

    def _enable_dhcp_helper(self, network, enable_isolated_metadata=False,
                            is_isolated_network=False):
        self.dhcp._process_monitor = mock.Mock()
        if enable_isolated_metadata:
            cfg.CONF.set_override('enable_isolated_metadata', True)
        self.plugin.get_network_info.return_value = network
        self.dhcp.enable_dhcp_helper(network.id)
        self.plugin.assert_has_calls([
            mock.call.get_network_info(network.id)])
        self.call_driver.assert_called_once_with('enable', network)
        self.cache.assert_has_calls([mock.call.put(network)])
        if is_isolated_network:
            self.external_process.assert_has_calls([
                self._process_manager_constructor_call(),
                mock.call().enable()
            ])
        else:
            self.assertFalse(self.external_process.call_count)

    def test_enable_dhcp_helper_enable_metadata_isolated_network(self):
        self._enable_dhcp_helper(isolated_network,
                                 enable_isolated_metadata=True,
                                 is_isolated_network=True)

    def test_enable_dhcp_helper_enable_metadata_no_gateway(self):
        isolated_network_no_gateway = copy.deepcopy(isolated_network)
        isolated_network_no_gateway.subnets[0].gateway_ip = None

        self._enable_dhcp_helper(isolated_network_no_gateway,
                                 enable_isolated_metadata=True,
                                 is_isolated_network=True)

    def test_enable_dhcp_helper_enable_metadata_nonisolated_network(self):
        nonisolated_network = copy.deepcopy(isolated_network)
        nonisolated_network.ports[0].device_owner = (
            const.DEVICE_OWNER_ROUTER_INTF)
        nonisolated_network.ports[0].fixed_ips[0].ip_address = '172.9.9.1'

        self._enable_dhcp_helper(nonisolated_network,
                                 enable_isolated_metadata=True,
                                 is_isolated_network=False)

    def test_enable_dhcp_helper_enable_metadata_nonisolated_dist_network(self):
        nonisolated_dist_network.ports[0].device_owner = (
            const.DEVICE_OWNER_ROUTER_INTF)
        nonisolated_dist_network.ports[0].fixed_ips[0].ip_address = '172.9.9.1'
        nonisolated_dist_network.ports[1].device_owner = (
            const.DEVICE_OWNER_DVR_INTERFACE)
        nonisolated_dist_network.ports[1].fixed_ips[0].ip_address = '172.9.9.1'

        self._enable_dhcp_helper(nonisolated_dist_network,
                                 enable_isolated_metadata=True,
                                 is_isolated_network=False)

    def test_enable_dhcp_helper_enable_metadata_empty_network(self):
        self._enable_dhcp_helper(empty_network,
                                 enable_isolated_metadata=True,
                                 is_isolated_network=True)

    def test_enable_dhcp_helper_enable_metadata_ipv6_ipv4_network(self):
        self._enable_dhcp_helper(fake_network_ipv6_ipv4,
                                 enable_isolated_metadata=True,
                                 is_isolated_network=True)

    def test_enable_dhcp_helper_driver_failure_ipv6_ipv4_network(self):
        self.plugin.get_network_info.return_value = fake_network_ipv6_ipv4
        self.call_driver.return_value = False
        cfg.CONF.set_override('enable_isolated_metadata', True)
        with mock.patch.object(
            self.dhcp, 'enable_isolated_metadata_proxy') as enable_metadata:
            self.dhcp.enable_dhcp_helper(fake_network_ipv6_ipv4.id)
            self.plugin.assert_has_calls(
                [mock.call.get_network_info(fake_network_ipv6_ipv4.id)])
            self.call_driver.assert_called_once_with('enable',
                                                     fake_network_ipv6_ipv4)
            self.assertFalse(self.cache.called)
            self.assertFalse(enable_metadata.called)
            self.assertFalse(self.external_process.called)

    def test_enable_dhcp_helper(self):
        self._enable_dhcp_helper(fake_network)

    def test_enable_dhcp_helper_ipv6_network(self):
        self._enable_dhcp_helper(fake_network_ipv6)

    def test_enable_dhcp_helper_down_network(self):
        self.plugin.get_network_info.return_value = fake_down_network
        self.dhcp.enable_dhcp_helper(fake_down_network.id)
        self.plugin.assert_has_calls(
            [mock.call.get_network_info(fake_down_network.id)])
        self.assertFalse(self.call_driver.called)
        self.assertFalse(self.cache.called)
        self.assertFalse(self.external_process.called)

    def test_enable_dhcp_helper_network_none(self):
        self.plugin.get_network_info.return_value = None
        with mock.patch.object(dhcp_agent.LOG, 'warn') as log:
            self.dhcp.enable_dhcp_helper('fake_id')
            self.plugin.assert_has_calls(
                [mock.call.get_network_info('fake_id')])
            self.assertFalse(self.call_driver.called)
            self.assertTrue(log.called)
            self.assertFalse(self.dhcp.schedule_resync.called)

    def test_enable_dhcp_helper_exception_during_rpc(self):
        self.plugin.get_network_info.side_effect = Exception
        with mock.patch.object(dhcp_agent.LOG, 'exception') as log:
            self.dhcp.enable_dhcp_helper(fake_network.id)
            self.plugin.assert_has_calls(
                [mock.call.get_network_info(fake_network.id)])
            self.assertFalse(self.call_driver.called)
            self.assertTrue(log.called)
            self.assertTrue(self.schedule_resync.called)
            self.assertFalse(self.cache.called)
            self.assertFalse(self.external_process.called)

    def test_enable_dhcp_helper_driver_failure(self):
        self.plugin.get_network_info.return_value = fake_network
        self.call_driver.return_value = False
        self.dhcp.enable_dhcp_helper(fake_network.id)
        self.plugin.assert_has_calls(
            [mock.call.get_network_info(fake_network.id)])
        self.call_driver.assert_called_once_with('enable', fake_network)
        self.assertFalse(self.cache.called)
        self.assertFalse(self.external_process.called)

    def _disable_dhcp_helper_known_network(self, isolated_metadata=False):
        if isolated_metadata:
            cfg.CONF.set_override('enable_isolated_metadata', True)
        self.cache.get_network_by_id.return_value = fake_network
        self.dhcp.disable_dhcp_helper(fake_network.id)
        self.cache.assert_has_calls(
            [mock.call.get_network_by_id(fake_network.id)])
        self.call_driver.assert_called_once_with('disable', fake_network)
        if isolated_metadata:
            self.external_process.assert_has_calls([
                self._process_manager_constructor_call(ns=None),
                mock.call().disable()])
        else:
            self.assertFalse(self.external_process.call_count)

    def test_disable_dhcp_helper_known_network_isolated_metadata(self):
        self._disable_dhcp_helper_known_network(isolated_metadata=True)

    def test_disable_dhcp_helper_known_network(self):
        self._disable_dhcp_helper_known_network()

    def test_disable_dhcp_helper_unknown_network(self):
        self.cache.get_network_by_id.return_value = None
        self.dhcp.disable_dhcp_helper('abcdef')
        self.cache.assert_has_calls(
            [mock.call.get_network_by_id('abcdef')])
        self.assertEqual(0, self.call_driver.call_count)
        self.assertFalse(self.external_process.called)

    def _disable_dhcp_helper_driver_failure(self, isolated_metadata=False):
        if isolated_metadata:
            cfg.CONF.set_override('enable_isolated_metadata', True)
        self.cache.get_network_by_id.return_value = fake_network
        self.call_driver.return_value = False
        self.dhcp.disable_dhcp_helper(fake_network.id)
        self.cache.assert_has_calls(
            [mock.call.get_network_by_id(fake_network.id)])
        self.call_driver.assert_called_once_with('disable', fake_network)
        self.cache.assert_has_calls(
            [mock.call.get_network_by_id(fake_network.id)])
        if isolated_metadata:
            self.external_process.assert_has_calls([
                self._process_manager_constructor_call(ns=None),
                mock.call().disable()
            ])
        else:
            self.assertFalse(self.external_process.call_count)

    def test_disable_dhcp_helper_driver_failure_isolated_metadata(self):
        self._disable_dhcp_helper_driver_failure(isolated_metadata=True)

    def test_disable_dhcp_helper_driver_failure(self):
        self._disable_dhcp_helper_driver_failure()

    def test_enable_isolated_metadata_proxy(self):
        self.dhcp._process_monitor = mock.Mock()
        self.dhcp.enable_isolated_metadata_proxy(fake_network)
        self.external_process.assert_has_calls([
            self._process_manager_constructor_call(),
            mock.call().enable()
        ])

    def test_disable_isolated_metadata_proxy(self):
        method_path = ('neutron.agent.metadata.driver.MetadataDriver'
                       '.destroy_monitored_metadata_proxy')
        with mock.patch(method_path) as destroy:
            self.dhcp.disable_isolated_metadata_proxy(fake_network)
            destroy.assert_called_once_with(self.dhcp._process_monitor,
                                            fake_network.id,
                                            cfg.CONF)

    def _test_metadata_network(self, network):
        cfg.CONF.set_override('enable_metadata_network', True)
        cfg.CONF.set_override('debug', True)
        cfg.CONF.set_override('verbose', False)
        cfg.CONF.set_override('log_file', 'test.log')
        method_path = ('neutron.agent.metadata.driver.MetadataDriver'
                       '.spawn_monitored_metadata_proxy')
        with mock.patch(method_path) as spawn:
            self.dhcp.enable_isolated_metadata_proxy(network)
            spawn.assert_called_once_with(self.dhcp._process_monitor,
                                          network.namespace,
                                          dhcp.METADATA_PORT,
                                          cfg.CONF,
                                          router_id='forzanapoli')

    def test_enable_isolated_metadata_proxy_with_metadata_network(self):
        self._test_metadata_network(fake_meta_network)

    def test_enable_isolated_metadata_proxy_with_metadata_network_dvr(self):
        self._test_metadata_network(fake_meta_dvr_network)

    def test_enable_isolated_metadata_proxy_with_dist_network(self):
        self._test_metadata_network(fake_dist_network)

    def test_network_create_end(self):
        payload = dict(network=dict(id=fake_network.id))

        with mock.patch.object(self.dhcp, 'enable_dhcp_helper') as enable:
            self.dhcp.network_create_end(None, payload)
            enable.assert_called_once_with(fake_network.id)

    def test_network_update_end_admin_state_up(self):
        payload = dict(network=dict(id=fake_network.id, admin_state_up=True))
        with mock.patch.object(self.dhcp, 'enable_dhcp_helper') as enable:
            self.dhcp.network_update_end(None, payload)
            enable.assert_called_once_with(fake_network.id)

    def test_network_update_end_admin_state_down(self):
        payload = dict(network=dict(id=fake_network.id, admin_state_up=False))
        with mock.patch.object(self.dhcp, 'disable_dhcp_helper') as disable:
            self.dhcp.network_update_end(None, payload)
            disable.assert_called_once_with(fake_network.id)

    def test_network_delete_end(self):
        payload = dict(network_id=fake_network.id)

        with mock.patch.object(self.dhcp, 'disable_dhcp_helper') as disable:
            self.dhcp.network_delete_end(None, payload)
            disable.assert_called_once_with(fake_network.id)

    def test_refresh_dhcp_helper_no_dhcp_enabled_networks(self):
        network = dhcp.NetModel(True, dict(id='net-id',
                                tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa',
                                admin_state_up=True,
                                subnets=[],
                                ports=[]))

        self.cache.get_network_by_id.return_value = network
        self.plugin.get_network_info.return_value = network
        with mock.patch.object(self.dhcp, 'disable_dhcp_helper') as disable:
            self.dhcp.refresh_dhcp_helper(network.id)
            disable.assert_called_once_with(network.id)
            self.assertFalse(self.cache.called)
            self.assertFalse(self.call_driver.called)
            self.cache.assert_has_calls(
                [mock.call.get_network_by_id('net-id')])

    def test_refresh_dhcp_helper_exception_during_rpc(self):
        network = dhcp.NetModel(True, dict(id='net-id',
                                tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa',
                                admin_state_up=True,
                                subnets=[],
                                ports=[]))

        self.cache.get_network_by_id.return_value = network
        self.plugin.get_network_info.side_effect = Exception
        with mock.patch.object(dhcp_agent.LOG, 'exception') as log:
            self.dhcp.refresh_dhcp_helper(network.id)
            self.assertFalse(self.call_driver.called)
            self.cache.assert_has_calls(
                [mock.call.get_network_by_id('net-id')])
            self.assertTrue(log.called)
            self.assertTrue(self.dhcp.schedule_resync.called)

    def test_subnet_update_end(self):
        payload = dict(subnet=dict(network_id=fake_network.id))
        self.cache.get_network_by_id.return_value = fake_network
        self.plugin.get_network_info.return_value = fake_network

        self.dhcp.subnet_update_end(None, payload)

        self.cache.assert_has_calls([mock.call.put(fake_network)])
        self.call_driver.assert_called_once_with('reload_allocations',
                                                 fake_network)

    def test_subnet_update_end_restart(self):
        new_state = dhcp.NetModel(True, dict(id=fake_network.id,
                                  tenant_id=fake_network.tenant_id,
                                  admin_state_up=True,
                                  subnets=[fake_subnet1, fake_subnet3],
                                  ports=[fake_port1]))

        payload = dict(subnet=dict(network_id=fake_network.id))
        self.cache.get_network_by_id.return_value = fake_network
        self.plugin.get_network_info.return_value = new_state

        self.dhcp.subnet_update_end(None, payload)

        self.cache.assert_has_calls([mock.call.put(new_state)])
        self.call_driver.assert_called_once_with('restart',
                                                 new_state)

    def test_subnet_update_end_delete_payload(self):
        prev_state = dhcp.NetModel(True, dict(id=fake_network.id,
                                   tenant_id=fake_network.tenant_id,
                                   admin_state_up=True,
                                   subnets=[fake_subnet1, fake_subnet3],
                                   ports=[fake_port1]))

        payload = dict(subnet_id=fake_subnet1.id)
        self.cache.get_network_by_subnet_id.return_value = prev_state
        self.cache.get_network_by_id.return_value = prev_state
        self.plugin.get_network_info.return_value = fake_network

        self.dhcp.subnet_delete_end(None, payload)

        self.cache.assert_has_calls([
            mock.call.get_network_by_subnet_id(
                'bbbbbbbb-bbbb-bbbb-bbbbbbbbbbbb'),
            mock.call.get_network_by_id('12345678-1234-5678-1234567890ab'),
            mock.call.put(fake_network)])
        self.call_driver.assert_called_once_with('restart',
                                                 fake_network)

    def test_port_update_end(self):
        payload = dict(port=fake_port2)
        self.cache.get_network_by_id.return_value = fake_network
        self.cache.get_port_by_id.return_value = fake_port2
        self.dhcp.port_update_end(None, payload)
        self.cache.assert_has_calls(
            [mock.call.get_network_by_id(fake_port2.network_id),
             mock.call.put_port(mock.ANY)])
        self.call_driver.assert_called_once_with('reload_allocations',
                                                 fake_network)

    def test_port_update_change_ip_on_port(self):
        payload = dict(port=fake_port1)
        self.cache.get_network_by_id.return_value = fake_network
        updated_fake_port1 = copy.deepcopy(fake_port1)
        updated_fake_port1.fixed_ips[0].ip_address = '172.9.9.99'
        self.cache.get_port_by_id.return_value = updated_fake_port1
        self.dhcp.port_update_end(None, payload)
        self.cache.assert_has_calls(
            [mock.call.get_network_by_id(fake_port1.network_id),
             mock.call.put_port(mock.ANY)])
        self.call_driver.assert_has_calls(
            [mock.call.call_driver('reload_allocations', fake_network)])

    def test_port_update_change_ip_on_dhcp_agents_port(self):
        self.cache.get_network_by_id.return_value = fake_network
        self.cache.get_port_by_id.return_value = fake_port1
        payload = dict(port=copy.deepcopy(fake_port1))
        device_id = utils.get_dhcp_agent_device_id(
            payload['port']['network_id'], self.dhcp.conf.host)
        payload['port']['fixed_ips'][0]['ip_address'] = '172.9.9.99'
        payload['port']['device_id'] = device_id
        self.dhcp.port_update_end(None, payload)
        self.call_driver.assert_has_calls(
            [mock.call.call_driver('restart', fake_network)])

    def test_port_update_on_dhcp_agents_port_no_ip_change(self):
        self.cache.get_network_by_id.return_value = fake_network
        self.cache.get_port_by_id.return_value = fake_port1
        payload = dict(port=fake_port1)
        device_id = utils.get_dhcp_agent_device_id(
            payload['port']['network_id'], self.dhcp.conf.host)
        payload['port']['device_id'] = device_id
        self.dhcp.port_update_end(None, payload)
        self.call_driver.assert_has_calls(
            [mock.call.call_driver('reload_allocations', fake_network)])

    def test_port_delete_end(self):
        payload = dict(port_id=fake_port2.id)
        self.cache.get_network_by_id.return_value = fake_network
        self.cache.get_port_by_id.return_value = fake_port2

        self.dhcp.port_delete_end(None, payload)
        self.cache.assert_has_calls(
            [mock.call.get_port_by_id(fake_port2.id),
             mock.call.get_network_by_id(fake_network.id),
             mock.call.remove_port(fake_port2)])
        self.call_driver.assert_has_calls(
            [mock.call.call_driver('reload_allocations', fake_network)])

    def test_port_delete_end_unknown_port(self):
        payload = dict(port_id='unknown')
        self.cache.get_port_by_id.return_value = None

        self.dhcp.port_delete_end(None, payload)

        self.cache.assert_has_calls([mock.call.get_port_by_id('unknown')])
        self.assertEqual(self.call_driver.call_count, 0)


class TestDhcpPluginApiProxy(base.BaseTestCase):
    def _test_dhcp_api(self, method, **kwargs):
        ctxt = context.get_admin_context()
        proxy = dhcp_agent.DhcpPluginApi('foo', ctxt, None)
        proxy.host = 'foo'

        with mock.patch.object(proxy.client, 'call') as rpc_mock,\
                mock.patch.object(proxy.client, 'prepare') as prepare_mock:
            prepare_mock.return_value = proxy.client
            rpc_mock.return_value = kwargs.pop('return_value', [])

            prepare_args = {}
            if 'version' in kwargs:
                prepare_args['version'] = kwargs.pop('version')

            retval = getattr(proxy, method)(**kwargs)
            self.assertEqual(retval, rpc_mock.return_value)

            prepare_mock.assert_called_once_with(**prepare_args)
            kwargs['host'] = proxy.host
            rpc_mock.assert_called_once_with(ctxt, method, **kwargs)

    def test_get_active_networks_info(self):
        self._test_dhcp_api('get_active_networks_info', version='1.1')

    def test_get_network_info(self):
        self._test_dhcp_api('get_network_info', network_id='fake_id',
                            return_value=None)

    def test_create_dhcp_port(self):
        self._test_dhcp_api('create_dhcp_port', port='fake_port',
                            return_value=None, version='1.1')

    def test_update_dhcp_port(self):
        self._test_dhcp_api('update_dhcp_port', port_id='fake_id',
                            port='fake_port', return_value=None, version='1.1')

    def test_release_dhcp_port(self):
        self._test_dhcp_api('release_dhcp_port', network_id='fake_id',
                            device_id='fake_id_2')

    def test_release_port_fixed_ip(self):
        self._test_dhcp_api('release_port_fixed_ip', network_id='fake_id',
                            device_id='fake_id_2', subnet_id='fake_id_3')


class TestNetworkCache(base.BaseTestCase):
    def test_put_network(self):
        nc = dhcp_agent.NetworkCache()
        nc.put(fake_network)
        self.assertEqual(nc.cache,
                         {fake_network.id: fake_network})
        self.assertEqual(nc.subnet_lookup,
                         {fake_subnet1.id: fake_network.id,
                          fake_subnet2.id: fake_network.id})
        self.assertEqual(nc.port_lookup,
                         {fake_port1.id: fake_network.id})

    def test_put_network_existing(self):
        prev_network_info = mock.Mock()
        nc = dhcp_agent.NetworkCache()
        with mock.patch.object(nc, 'remove') as remove:
            nc.cache[fake_network.id] = prev_network_info

            nc.put(fake_network)
            remove.assert_called_once_with(prev_network_info)
        self.assertEqual(nc.cache,
                         {fake_network.id: fake_network})
        self.assertEqual(nc.subnet_lookup,
                         {fake_subnet1.id: fake_network.id,
                          fake_subnet2.id: fake_network.id})
        self.assertEqual(nc.port_lookup,
                         {fake_port1.id: fake_network.id})

    def test_remove_network(self):
        nc = dhcp_agent.NetworkCache()
        nc.cache = {fake_network.id: fake_network}
        nc.subnet_lookup = {fake_subnet1.id: fake_network.id,
                            fake_subnet2.id: fake_network.id}
        nc.port_lookup = {fake_port1.id: fake_network.id}
        nc.remove(fake_network)

        self.assertEqual(len(nc.cache), 0)
        self.assertEqual(len(nc.subnet_lookup), 0)
        self.assertEqual(len(nc.port_lookup), 0)

    def test_get_network_by_id(self):
        nc = dhcp_agent.NetworkCache()
        nc.put(fake_network)

        self.assertEqual(nc.get_network_by_id(fake_network.id), fake_network)

    def test_get_network_ids(self):
        nc = dhcp_agent.NetworkCache()
        nc.put(fake_network)

        self.assertEqual(list(nc.get_network_ids()), [fake_network.id])

    def test_get_network_by_subnet_id(self):
        nc = dhcp_agent.NetworkCache()
        nc.put(fake_network)

        self.assertEqual(nc.get_network_by_subnet_id(fake_subnet1.id),
                         fake_network)

    def test_get_network_by_port_id(self):
        nc = dhcp_agent.NetworkCache()
        nc.put(fake_network)

        self.assertEqual(nc.get_network_by_port_id(fake_port1.id),
                         fake_network)

    def test_put_port(self):
        fake_net = dhcp.NetModel(
            True, dict(id='12345678-1234-5678-1234567890ab',
                       tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa',
                       subnets=[fake_subnet1],
                       ports=[fake_port1]))
        nc = dhcp_agent.NetworkCache()
        nc.put(fake_net)
        nc.put_port(fake_port2)
        self.assertEqual(len(nc.port_lookup), 2)
        self.assertIn(fake_port2, fake_net.ports)

    def test_put_port_existing(self):
        fake_net = dhcp.NetModel(
            True, dict(id='12345678-1234-5678-1234567890ab',
                       tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa',
                       subnets=[fake_subnet1],
                       ports=[fake_port1, fake_port2]))
        nc = dhcp_agent.NetworkCache()
        nc.put(fake_net)
        nc.put_port(fake_port2)

        self.assertEqual(len(nc.port_lookup), 2)
        self.assertIn(fake_port2, fake_net.ports)

    def test_remove_port_existing(self):
        fake_net = dhcp.NetModel(
            True, dict(id='12345678-1234-5678-1234567890ab',
                       tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa',
                       subnets=[fake_subnet1],
                       ports=[fake_port1, fake_port2]))
        nc = dhcp_agent.NetworkCache()
        nc.put(fake_net)
        nc.remove_port(fake_port2)

        self.assertEqual(len(nc.port_lookup), 1)
        self.assertNotIn(fake_port2, fake_net.ports)

    def test_get_port_by_id(self):
        nc = dhcp_agent.NetworkCache()
        nc.put(fake_network)
        self.assertEqual(nc.get_port_by_id(fake_port1.id), fake_port1)


class FakePort1(object):
    id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'


class FakeV4Subnet(object):
    id = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
    ip_version = 4
    cidr = '192.168.0.0/24'
    gateway_ip = '192.168.0.1'
    enable_dhcp = True


class FakeV4SubnetNoGateway(object):
    id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
    ip_version = 4
    cidr = '192.168.1.0/24'
    gateway_ip = None
    enable_dhcp = True


class FakeV4Network(object):
    id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    subnets = [FakeV4Subnet()]
    ports = [FakePort1()]
    namespace = 'qdhcp-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'


class FakeV4NetworkNoSubnet(object):
    id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    subnets = []
    ports = []


class FakeV4NetworkNoGateway(object):
    id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
    subnets = [FakeV4SubnetNoGateway()]
    ports = [FakePort1()]


class TestDeviceManager(base.BaseTestCase):
    def setUp(self):
        super(TestDeviceManager, self).setUp()
        config.register_interface_driver_opts_helper(cfg.CONF)
        config.register_use_namespaces_opts_helper(cfg.CONF)
        cfg.CONF.register_opts(dhcp_config.DHCP_AGENT_OPTS)
        cfg.CONF.set_override('interface_driver',
                              'neutron.agent.linux.interface.NullDriver')
        cfg.CONF.set_override('use_namespaces', True)
        cfg.CONF.set_override('enable_isolated_metadata', True)

        self.ensure_device_is_ready_p = mock.patch(
            'neutron.agent.linux.ip_lib.ensure_device_is_ready')
        self.ensure_device_is_ready = (self.ensure_device_is_ready_p.start())

        self.dvr_cls_p = mock.patch('neutron.agent.linux.interface.NullDriver')
        self.iproute_cls_p = mock.patch('neutron.agent.linux.'
                                        'ip_lib.IpRouteCommand')
        driver_cls = self.dvr_cls_p.start()
        iproute_cls = self.iproute_cls_p.start()
        self.mock_driver = mock.MagicMock()
        self.mock_driver.DEV_NAME_LEN = (
            interface.LinuxInterfaceDriver.DEV_NAME_LEN)
        self.mock_iproute = mock.MagicMock()
        driver_cls.return_value = self.mock_driver
        iproute_cls.return_value = self.mock_iproute

        iptables_cls_p = mock.patch(
            'neutron.agent.linux.iptables_manager.IptablesManager')
        iptables_cls = iptables_cls_p.start()
        self.iptables_inst = mock.Mock()
        iptables_cls.return_value = self.iptables_inst
        self.mangle_inst = mock.Mock()
        self.iptables_inst.ipv4 = {'mangle': self.mangle_inst}

    def _test_setup_helper(self, device_is_ready, net=None, port=None):
        net = net or fake_network
        port = port or fake_port1
        plugin = mock.Mock()
        plugin.create_dhcp_port.return_value = port or fake_port1
        self.ensure_device_is_ready.return_value = device_is_ready
        self.mock_driver.get_device_name.return_value = 'tap12345678-12'

        dh = dhcp.DeviceManager(cfg.CONF, plugin)
        dh._set_default_route = mock.Mock()
        interface_name = dh.setup(net)

        self.assertEqual(interface_name, 'tap12345678-12')

        plugin.assert_has_calls([
            mock.call.create_dhcp_port(
                {'port': {'name': '', 'admin_state_up': True,
                          'network_id': net.id, 'tenant_id': net.tenant_id,
                          'fixed_ips':
                          [{'subnet_id': port.fixed_ips[0].subnet_id}],
                          'device_id': mock.ANY}})])

        if port == fake_ipv6_port:
            expected_ips = ['169.254.169.254/16']
        else:
            expected_ips = ['172.9.9.9/24', '169.254.169.254/16']
        expected = [
            mock.call.get_device_name(port),
            mock.call.init_l3(
                'tap12345678-12',
                expected_ips,
                namespace=net.namespace)]

        if not device_is_ready:
            expected.insert(1,
                            mock.call.plug(net.id,
                                           port.id,
                                           'tap12345678-12',
                                           'aa:bb:cc:dd:ee:ff',
                                           namespace=net.namespace))
        self.mock_driver.assert_has_calls(expected)

        dh._set_default_route.assert_called_once_with(net, 'tap12345678-12')

    def test_setup(self):
        cfg.CONF.set_override('enable_metadata_network', False)
        self._test_setup_helper(False)
        cfg.CONF.set_override('enable_metadata_network', True)
        self._test_setup_helper(False)

    def test_setup_calls_fill_dhcp_udp_checksums(self):
        self._test_setup_helper(False)
        rule = ('-p udp --dport %d -j CHECKSUM --checksum-fill'
                % const.DHCP_RESPONSE_PORT)
        expected = [mock.call.add_rule('POSTROUTING', rule)]
        self.mangle_inst.assert_has_calls(expected)

    def test_setup_ipv6(self):
        self._test_setup_helper(True, net=fake_network_ipv6,
                                port=fake_ipv6_port)

    def test_setup_device_is_ready(self):
        self._test_setup_helper(True)

    def test_create_dhcp_port_raise_conflict(self):
        plugin = mock.Mock()
        dh = dhcp.DeviceManager(cfg.CONF, plugin)
        plugin.create_dhcp_port.return_value = None
        self.assertRaises(exceptions.Conflict,
                          dh.setup_dhcp_port,
                          fake_network)

    def test_create_dhcp_port_create_new(self):
        plugin = mock.Mock()
        dh = dhcp.DeviceManager(cfg.CONF, plugin)
        plugin.create_dhcp_port.return_value = fake_network.ports[0]
        dh.setup_dhcp_port(fake_network)
        plugin.assert_has_calls([
            mock.call.create_dhcp_port(
                {'port': {'name': '', 'admin_state_up': True,
                          'network_id':
                          fake_network.id, 'tenant_id': fake_network.tenant_id,
                          'fixed_ips':
                          [{'subnet_id': fake_fixed_ip1.subnet_id}],
                          'device_id': mock.ANY}})])

    def test_create_dhcp_port_update_add_subnet(self):
        plugin = mock.Mock()
        dh = dhcp.DeviceManager(cfg.CONF, plugin)
        fake_network_copy = copy.deepcopy(fake_network)
        fake_network_copy.ports[0].device_id = dh.get_device_id(fake_network)
        fake_network_copy.subnets[1].enable_dhcp = True
        plugin.update_dhcp_port.return_value = fake_network.ports[0]
        dh.setup_dhcp_port(fake_network_copy)
        port_body = {'port': {
                     'network_id': fake_network.id,
                     'fixed_ips': [{'subnet_id': fake_fixed_ip1.subnet_id,
                                    'ip_address': fake_fixed_ip1.ip_address},
                                   {'subnet_id': fake_subnet2.id}]}}

        plugin.assert_has_calls([
            mock.call.update_dhcp_port(fake_network_copy.ports[0].id,
                                       port_body)])

    def test_update_dhcp_port_raises_conflict(self):
        plugin = mock.Mock()
        dh = dhcp.DeviceManager(cfg.CONF, plugin)
        fake_network_copy = copy.deepcopy(fake_network)
        fake_network_copy.ports[0].device_id = dh.get_device_id(fake_network)
        fake_network_copy.subnets[1].enable_dhcp = True
        plugin.update_dhcp_port.return_value = None
        self.assertRaises(exceptions.Conflict,
                          dh.setup_dhcp_port,
                          fake_network_copy)

    def test_create_dhcp_port_no_update_or_create(self):
        plugin = mock.Mock()
        dh = dhcp.DeviceManager(cfg.CONF, plugin)
        fake_network_copy = copy.deepcopy(fake_network)
        fake_network_copy.ports[0].device_id = dh.get_device_id(fake_network)
        dh.setup_dhcp_port(fake_network_copy)
        self.assertFalse(plugin.setup_dhcp_port.called)
        self.assertFalse(plugin.update_dhcp_port.called)

    def test_setup_dhcp_port_with_non_enable_dhcp_subnet(self):
        plugin = mock.Mock()
        dh = dhcp.DeviceManager(cfg.CONF, plugin)
        fake_network_copy = copy.deepcopy(fake_network)
        fake_network_copy.ports[0].device_id = dh.get_device_id(fake_network)
        plugin.update_dhcp_port.return_value = fake_port1
        self.assertEqual(fake_subnet1.id,
                dh.setup_dhcp_port(fake_network_copy).fixed_ips[0].subnet_id)

    def test_destroy(self):
        fake_net = dhcp.NetModel(
            True, dict(id=FAKE_NETWORK_UUID,
                       tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa'))

        with mock.patch('neutron.agent.linux.interface.NullDriver') as dvr_cls:
            mock_driver = mock.MagicMock()
            mock_driver.get_device_name.return_value = 'tap12345678-12'
            dvr_cls.return_value = mock_driver

            plugin = mock.Mock()

            dh = dhcp.DeviceManager(cfg.CONF, plugin)
            dh.destroy(fake_net, 'tap12345678-12')

            dvr_cls.assert_called_once_with(cfg.CONF)
            mock_driver.assert_has_calls(
                [mock.call.unplug('tap12345678-12',
                                  namespace='qdhcp-' + fake_net.id)])
            plugin.assert_has_calls(
                [mock.call.release_dhcp_port(fake_net.id, mock.ANY)])

    def test_get_interface_name(self):
        fake_net = dhcp.NetModel(
            True, dict(id='12345678-1234-5678-1234567890ab',
                       tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa'))

        fake_port = dhcp.DictModel(
            dict(id='12345678-1234-aaaa-1234567890ab',
                 mac_address='aa:bb:cc:dd:ee:ff'))

        with mock.patch('neutron.agent.linux.interface.NullDriver') as dvr_cls:
            mock_driver = mock.MagicMock()
            mock_driver.get_device_name.return_value = 'tap12345678-12'
            dvr_cls.return_value = mock_driver

            plugin = mock.Mock()

            dh = dhcp.DeviceManager(cfg.CONF, plugin)
            dh.get_interface_name(fake_net, fake_port)

            dvr_cls.assert_called_once_with(cfg.CONF)
            mock_driver.assert_has_calls(
                [mock.call.get_device_name(fake_port)])

            self.assertEqual(len(plugin.mock_calls), 0)

    def test_get_device_id(self):
        fake_net = dhcp.NetModel(
            True, dict(id='12345678-1234-5678-1234567890ab',
                       tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa'))
        expected = ('dhcp1ae5f96c-c527-5079-82ea-371a01645457-12345678-1234-'
                    '5678-1234567890ab')

        with mock.patch('uuid.uuid5') as uuid5:
            uuid5.return_value = '1ae5f96c-c527-5079-82ea-371a01645457'

            dh = dhcp.DeviceManager(cfg.CONF, None)
            uuid5.called_once_with(uuid.NAMESPACE_DNS, cfg.CONF.host)
            self.assertEqual(dh.get_device_id(fake_net), expected)

    def test_update(self):
        # Try with namespaces and no metadata network
        cfg.CONF.set_override('use_namespaces', True)
        cfg.CONF.set_override('enable_metadata_network', False)
        dh = dhcp.DeviceManager(cfg.CONF, None)
        dh._set_default_route = mock.Mock()
        network = mock.Mock()

        dh.update(network, 'ns-12345678-12')

        dh._set_default_route.assert_called_once_with(network,
                                                      'ns-12345678-12')

        # No namespaces, shouldn't set default route.
        cfg.CONF.set_override('use_namespaces', False)
        cfg.CONF.set_override('enable_metadata_network', False)
        dh = dhcp.DeviceManager(cfg.CONF, None)
        dh._set_default_route = mock.Mock()

        dh.update(FakeV4Network(), 'tap12345678-12')

        self.assertFalse(dh._set_default_route.called)

        # Meta data network enabled, don't interfere with its gateway.
        cfg.CONF.set_override('use_namespaces', True)
        cfg.CONF.set_override('enable_metadata_network', True)
        dh = dhcp.DeviceManager(cfg.CONF, None)
        dh._set_default_route = mock.Mock()

        dh.update(FakeV4Network(), 'ns-12345678-12')

        self.assertTrue(dh._set_default_route.called)

        # For completeness
        cfg.CONF.set_override('use_namespaces', False)
        cfg.CONF.set_override('enable_metadata_network', True)
        dh = dhcp.DeviceManager(cfg.CONF, None)
        dh._set_default_route = mock.Mock()

        dh.update(FakeV4Network(), 'ns-12345678-12')

        self.assertFalse(dh._set_default_route.called)

    def test_set_default_route(self):
        dh = dhcp.DeviceManager(cfg.CONF, None)
        with mock.patch.object(dhcp.ip_lib, 'IPDevice') as mock_IPDevice:
            device = mock.Mock()
            mock_IPDevice.return_value = device
            device.route.get_gateway.return_value = None
            # Basic one subnet with gateway.
            network = FakeV4Network()
            dh._set_default_route(network, 'tap-name')

        self.assertEqual(device.route.get_gateway.call_count, 1)
        self.assertFalse(device.route.delete_gateway.called)
        device.route.add_gateway.assert_called_once_with('192.168.0.1')

    def test_set_default_route_no_subnet(self):
        dh = dhcp.DeviceManager(cfg.CONF, None)
        with mock.patch.object(dhcp.ip_lib, 'IPDevice') as mock_IPDevice:
            device = mock.Mock()
            mock_IPDevice.return_value = device
            device.route.get_gateway.return_value = None
            network = FakeV4NetworkNoSubnet()
            network.namespace = 'qdhcp-1234'
            dh._set_default_route(network, 'tap-name')

        self.assertEqual(device.route.get_gateway.call_count, 1)
        self.assertFalse(device.route.delete_gateway.called)
        self.assertFalse(device.route.add_gateway.called)

    def test_set_default_route_no_subnet_delete_gateway(self):
        dh = dhcp.DeviceManager(cfg.CONF, None)
        with mock.patch.object(dhcp.ip_lib, 'IPDevice') as mock_IPDevice:
            device = mock.Mock()
            mock_IPDevice.return_value = device
            device.route.get_gateway.return_value = dict(gateway='192.168.0.1')
            network = FakeV4NetworkNoSubnet()
            network.namespace = 'qdhcp-1234'
            dh._set_default_route(network, 'tap-name')

        self.assertEqual(device.route.get_gateway.call_count, 1)
        device.route.delete_gateway.assert_called_once_with('192.168.0.1')
        self.assertFalse(device.route.add_gateway.called)

    def test_set_default_route_no_gateway(self):
        dh = dhcp.DeviceManager(cfg.CONF, None)
        with mock.patch.object(dhcp.ip_lib, 'IPDevice') as mock_IPDevice:
            device = mock.Mock()
            mock_IPDevice.return_value = device
            device.route.get_gateway.return_value = dict(gateway='192.168.0.1')
            network = FakeV4NetworkNoGateway()
            network.namespace = 'qdhcp-1234'
            dh._set_default_route(network, 'tap-name')

        self.assertEqual(device.route.get_gateway.call_count, 1)
        device.route.delete_gateway.assert_called_once_with('192.168.0.1')
        self.assertFalse(device.route.add_gateway.called)

    def test_set_default_route_do_nothing(self):
        dh = dhcp.DeviceManager(cfg.CONF, None)
        with mock.patch.object(dhcp.ip_lib, 'IPDevice') as mock_IPDevice:
            device = mock.Mock()
            mock_IPDevice.return_value = device
            device.route.get_gateway.return_value = dict(gateway='192.168.0.1')
            network = FakeV4Network()
            dh._set_default_route(network, 'tap-name')

        self.assertEqual(device.route.get_gateway.call_count, 1)
        self.assertFalse(device.route.delete_gateway.called)
        self.assertFalse(device.route.add_gateway.called)

    def test_set_default_route_change_gateway(self):
        dh = dhcp.DeviceManager(cfg.CONF, None)
        with mock.patch.object(dhcp.ip_lib, 'IPDevice') as mock_IPDevice:
            device = mock.Mock()
            mock_IPDevice.return_value = device
            device.route.get_gateway.return_value = dict(gateway='192.168.0.2')
            network = FakeV4Network()
            dh._set_default_route(network, 'tap-name')

        self.assertEqual(device.route.get_gateway.call_count, 1)
        self.assertFalse(device.route.delete_gateway.called)
        device.route.add_gateway.assert_called_once_with('192.168.0.1')

    def test_set_default_route_two_subnets(self):
        # Try two subnets. Should set gateway from the first.
        dh = dhcp.DeviceManager(cfg.CONF, None)
        with mock.patch.object(dhcp.ip_lib, 'IPDevice') as mock_IPDevice:
            device = mock.Mock()
            mock_IPDevice.return_value = device
            device.route.get_gateway.return_value = None
            network = FakeV4Network()
            subnet2 = FakeV4Subnet()
            subnet2.gateway_ip = '192.168.1.1'
            network.subnets = [subnet2, FakeV4Subnet()]
            dh._set_default_route(network, 'tap-name')

        self.assertEqual(device.route.get_gateway.call_count, 1)
        self.assertFalse(device.route.delete_gateway.called)
        device.route.add_gateway.assert_called_once_with('192.168.1.1')


class TestDictModel(base.BaseTestCase):
    def test_basic_dict(self):
        d = dict(a=1, b=2)

        m = dhcp.DictModel(d)
        self.assertEqual(m.a, 1)
        self.assertEqual(m.b, 2)

    def test_dict_has_sub_dict(self):
        d = dict(a=dict(b=2))
        m = dhcp.DictModel(d)
        self.assertEqual(m.a.b, 2)

    def test_dict_contains_list(self):
        d = dict(a=[1, 2])

        m = dhcp.DictModel(d)
        self.assertEqual(m.a, [1, 2])

    def test_dict_contains_list_of_dicts(self):
        d = dict(a=[dict(b=2), dict(c=3)])

        m = dhcp.DictModel(d)
        self.assertEqual(m.a[0].b, 2)
        self.assertEqual(m.a[1].c, 3)


class TestNetModel(base.BaseTestCase):
    def test_ns_name(self):
        network = dhcp.NetModel(True, {'id': 'foo'})
        self.assertEqual(network.namespace, 'qdhcp-foo')

    def test_ns_name_false_namespace(self):
        network = dhcp.NetModel(False, {'id': 'foo'})
        self.assertIsNone(network.namespace)

    def test_ns_name_none_namespace(self):
        network = dhcp.NetModel(None, {'id': 'foo'})
        self.assertIsNone(network.namespace)
