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
import datetime
import signal
import sys
from unittest import mock
import uuid

import eventlet
from neutron_lib.agent import constants as agent_consts
from neutron_lib import constants as const
from neutron_lib import exceptions
from oslo_config import cfg
import oslo_messaging
from oslo_utils import netutils
from oslo_utils import timeutils
import testtools

from neutron.agent.dhcp import agent as dhcp_agent
from neutron.agent import dhcp_agent as entry
from neutron.agent.linux import dhcp
from neutron.agent.linux import interface
from neutron.agent.linux import utils as linux_utils
from neutron.agent.metadata import driver as metadata_driver
from neutron.common import config as common_config
from neutron.common import utils
from neutron.conf.agent import common as config
from neutron.conf.agent import dhcp as dhcp_config
from neutron.tests import base


HOSTNAME = 'hostname'
dev_man = dhcp.DeviceManager
rpc_api = dhcp_agent.DhcpPluginApi
DEVICE_MANAGER = '%s.%s' % (dev_man.__module__, dev_man.__name__)
DHCP_PLUGIN = '%s.%s' % (rpc_api.__module__, rpc_api.__name__)
FAKE_NETWORK_UUID = '12345678-1234-5678-1234567890ab'
FAKE_NETWORK_DHCP_NS = "qdhcp-%s" % FAKE_NETWORK_UUID
FAKE_PROJECT_ID = 'aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa'
FAKE_PRIORITY = 6
FAKE_V4_SUBNETPOOL_ID = 'kkkkkkkk-kkkk-kkkk-kkkk-kkkkkkkkkkkk'
FAKE_V6_SUBNETPOOL_ID = 'jjjjjjjj-jjjj-jjjj-jjjj-jjjjjjjjjjjj'


fake_subnet1_allocation_pools = dhcp.DictModel(id='', start='172.9.9.2',
                                               end='172.9.9.254')
fake_subnet1 = dhcp.DictModel(id='bbbbbbbb-bbbb-bbbb-bbbbbbbbbbbb',
                              network_id=FAKE_NETWORK_UUID,
                              cidr='172.9.9.0/24', enable_dhcp=True, name='',
                              project_id=FAKE_PROJECT_ID,
                              gateway_ip='172.9.9.1', host_routes=[],
                              dns_nameservers=[],
                              ip_version=const.IP_VERSION_4,
                              subnetpool_id=FAKE_V4_SUBNETPOOL_ID,
                              ipv6_ra_mode=None, ipv6_address_mode=None,
                              allocation_pools=fake_subnet1_allocation_pools)

fake_subnet2_allocation_pools = dhcp.DictModel(id='', start='172.9.8.2',
                                               end='172.9.8.254')
fake_subnet2 = dhcp.DictModel(id='dddddddd-dddd-dddd-dddddddddddd',
                              network_id=FAKE_NETWORK_UUID,
                              cidr='172.9.8.0/24', enable_dhcp=False, name='',
                              project_id=FAKE_PROJECT_ID,
                              gateway_ip='172.9.8.1',
                              host_routes=[], dns_nameservers=[],
                              ip_version=const.IP_VERSION_4,
                              allocation_pools=fake_subnet2_allocation_pools)

fake_subnet3 = dhcp.DictModel(id='bbbbbbbb-1111-2222-bbbbbbbbbbbb',
                              network_id=FAKE_NETWORK_UUID,
                              cidr='192.168.1.1/24', enable_dhcp=True,
                              ip_version=const.IP_VERSION_4)

fake_ipv6_subnet = dhcp.DictModel(id='bbbbbbbb-1111-2222-bbbbbbbbbbbb',
                                  network_id=FAKE_NETWORK_UUID,
                                  cidr='2001:0db8::0/64', enable_dhcp=True,
                                  project_id=FAKE_PROJECT_ID,
                                  gateway_ip='2001:0db8::1',
                                  ip_version=const.IP_VERSION_6,
                                  ipv6_ra_mode='slaac', ipv6_address_mode=None)

fake_meta_subnet = dhcp.DictModel(dict(id='bbbbbbbb-1111-2222-bbbbbbbbbbbb',
                                       network_id=FAKE_NETWORK_UUID,
                                       cidr='169.254.169.252/30',
                                       gateway_ip='169.254.169.253',
                                       enable_dhcp=True,
                                       ip_version=const.IP_VERSION_4))

fake_fixed_ip1 = dhcp.DictModel(id='', subnet_id=fake_subnet1.id,
                                ip_address='172.9.9.9')
fake_fixed_ip_subnet2 = dhcp.DictModel(id='', subnet_id=fake_subnet2.id,
                                       ip_address='172.9.8.9')
fake_fixed_ip2 = dhcp.DictModel(id='', subnet_id=fake_subnet1.id,
                                ip_address='172.9.9.10')
fake_fixed_ipv6 = dhcp.DictModel(id='', subnet_id=fake_ipv6_subnet.id,
                                 ip_address='2001:db8::a8bb:ccff:fedd:ee99')
fake_meta_fixed_ip = dhcp.DictModel(id='', subnet=fake_meta_subnet,
                                    ip_address='169.254.169.254')
fake_allocation_pool_subnet1 = dhcp.DictModel(id='', start='172.9.9.2',
                                              end='172.9.9.254')

fake_port1 = dhcp.DictModel(id='12345678-1234-aaaa-1234567890ab',
                            device_id='dhcp-12345678-1234-aaaa-1234567890ab',
                            device_owner='',
                            allocation_pools=fake_subnet1_allocation_pools,
                            mac_address='aa:bb:cc:dd:ee:ff',
                            network_id=FAKE_NETWORK_UUID,
                            fixed_ips=[fake_fixed_ip1])

fake_dhcp_port = dhcp.DictModel(
    id='12345678-1234-aaaa-123456789022',
    device_id='dhcp-12345678-1234-aaaa-123456789022',
    device_owner=const.DEVICE_OWNER_DHCP,
    allocation_pools=fake_subnet1_allocation_pools,
    mac_address='aa:bb:cc:dd:ee:22',
    network_id=FAKE_NETWORK_UUID,
    fixed_ips=[fake_fixed_ip2],
    admin_state_up=True)

fake_port2 = dhcp.DictModel(id='12345678-1234-aaaa-123456789000',
                            device_id='dhcp-12345678-1234-aaaa-123456789000',
                            device_owner='',
                            mac_address='aa:bb:cc:dd:ee:99',
                            network_id=FAKE_NETWORK_UUID,
                            revision_number=77,
                            fixed_ips=[fake_fixed_ip2])

fake_port_subnet_2 = dhcp.DictModel(
        id='12345678-1234-aaaa-1234567890ab',
        device_id='dhcp-12345678-1234-aaaa-1234567890ab',
        device_owner='',
        allocation_pools=fake_subnet2_allocation_pools,
        mac_address='aa:bb:cc:dd:ee:ff',
        network_id=FAKE_NETWORK_UUID,
        fixed_ips=[fake_fixed_ip_subnet2])

fake_ipv6_port = dhcp.DictModel(id='12345678-1234-aaaa-123456789000',
                                device_owner='',
                                mac_address='aa:bb:cc:dd:ee:99',
                                network_id=FAKE_NETWORK_UUID,
                                fixed_ips=[fake_fixed_ipv6])

fake_meta_port = dhcp.DictModel(id='12345678-1234-aaaa-1234567890ab',
                                mac_address='aa:bb:cc:dd:ee:ff',
                                network_id=FAKE_NETWORK_UUID,
                                device_owner=const.DEVICE_OWNER_ROUTER_INTF,
                                device_id='forzanapoli',
                                fixed_ips=[fake_meta_fixed_ip])

fake_meta_dvr_port = dhcp.DictModel(fake_meta_port)
fake_meta_dvr_port['device_owner'] = const.DEVICE_OWNER_DVR_INTERFACE

fake_dist_port = dhcp.DictModel(id='12345678-1234-aaaa-1234567890ab',
                                mac_address='aa:bb:cc:dd:ee:ff',
                                network_id=FAKE_NETWORK_UUID,
                                device_owner=const.DEVICE_OWNER_DVR_INTERFACE,
                                device_id='forzanapoli',
                                fixed_ips=[fake_meta_fixed_ip])

fake_network = dhcp.NetModel(id=FAKE_NETWORK_UUID,
                             project_id=FAKE_PROJECT_ID,
                             admin_state_up=True,
                             subnets=[fake_subnet1, fake_subnet2],
                             ports=[fake_port1])

fake_network_no_dhcp_subnets = dhcp.NetModel(id=FAKE_NETWORK_UUID,
                                             project_id=FAKE_PROJECT_ID,
                                             admin_state_up=True,
                                             subnets=[fake_subnet2],
                                             ports=[fake_port_subnet_2])

fake_network_ipv6 = dhcp.NetModel(id=FAKE_NETWORK_UUID,
                                  project_id=FAKE_PROJECT_ID,
                                  admin_state_up=True,
                                  subnets=[fake_ipv6_subnet],
                                  ports=[fake_ipv6_port])

fake_network_ipv6_ipv4 = dhcp.NetModel(
    id=FAKE_NETWORK_UUID,
    project_id=FAKE_PROJECT_ID,
    admin_state_up=True,
    subnets=[fake_ipv6_subnet, fake_subnet1],
    ports=[fake_port1])

isolated_network = dhcp.NetModel(id=FAKE_NETWORK_UUID,
                                 project_id=FAKE_PROJECT_ID,
                                 admin_state_up=True,
                                 subnets=[fake_subnet1],
                                 ports=[fake_port1])

nonisolated_dist_network = dhcp.NetModel(id=FAKE_NETWORK_UUID,
                                         project_id=FAKE_PROJECT_ID,
                                         admin_state_up=True,
                                         subnets=[fake_subnet1],
                                         ports=[fake_port1, fake_port2])

empty_network = dhcp.NetModel(id=FAKE_NETWORK_UUID,
                              project_id=FAKE_PROJECT_ID,
                              admin_state_up=True,
                              subnets=[fake_subnet1],
                              ports=[])

fake_meta_network = dhcp.NetModel(id=FAKE_NETWORK_UUID,
                                  project_id=FAKE_PROJECT_ID,
                                  admin_state_up=True,
                                  subnets=[fake_meta_subnet],
                                  ports=[fake_meta_port])

fake_meta_dvr_network = dhcp.NetModel(fake_meta_network)
fake_meta_dvr_network['ports'] = [fake_meta_dvr_port]

fake_dist_network = dhcp.NetModel(id=FAKE_NETWORK_UUID,
                                  project_id=FAKE_PROJECT_ID,
                                  admin_state_up=True,
                                  subnets=[fake_meta_subnet],
                                  ports=[fake_meta_port, fake_dist_port])

fake_down_network = dhcp.NetModel(id='12345678-dddd-dddd-1234567890ab',
                                  project_id=FAKE_PROJECT_ID,
                                  admin_state_up=False,
                                  subnets=[],
                                  ports=[])


class TestDhcpAgent(base.BaseTestCase):

    def setUp(self):
        super(TestDhcpAgent, self).setUp()
        entry.register_options(cfg.CONF)
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
        self.mock_create_metadata_proxy_cfg = mock.patch(
            "neutron.agent.metadata.driver.HaproxyConfigurator")
        self.mock_create_metadata_proxy_cfg.start()
        self.mock_ip_wrapper_p = mock.patch("neutron.agent.linux.ip_lib."
                                            "IPWrapper")
        self.mock_ip_wrapper = self.mock_ip_wrapper_p.start()

    def test_init_resync_throttle_conf(self):
        try:
            dhcp_agent.DhcpAgent(HOSTNAME)
        except exceptions.InvalidConfigurationOption:
            self.fail("DHCP agent initialization unexpectedly raised an "
                      "InvalidConfigurationOption exception. No exception is "
                      "expected with the default configurations.")

        # default resync_interval = 5; default resync_throttle = 1
        cfg.CONF.set_override('resync_throttle', 10)
        # resync_throttle must be <= resync_interval, otherwise an
        # InvalidConfigurationOption exception would be raised with log
        # message.
        with mock.patch.object(dhcp_agent.LOG, 'exception') as log:
            with testtools.ExpectedException(
                    exceptions.InvalidConfigurationOption):
                dhcp_agent.DhcpAgent(HOSTNAME)
            log.assert_any_call("DHCP agent must have resync_throttle <= "
                                "resync_interval")

    def test_init_host(self):
        dhcp = dhcp_agent.DhcpAgent(HOSTNAME)
        with mock.patch.object(dhcp, 'sync_state') as sync_state:
            dhcp.init_host()
            sync_state.assert_called_once_with()

    def test_dhcp_agent_manager(self):
        state_rpc_str = 'neutron.agent.rpc.PluginReportStateAPI'
        # sync_state is needed for this test
        cfg.CONF.set_override('report_interval', 1, 'AGENT')
        mock_start_ready = mock.patch.object(
            dhcp_agent.DhcpAgentWithStateReport, 'start_ready_ports_loop',
            autospec=True).start()
        with mock.patch.object(dhcp_agent.DhcpAgentWithStateReport,
                               'periodic_resync',
                               autospec=True) as mock_periodic_resync:
            with mock.patch(state_rpc_str) as state_rpc:
                test_args = [
                    'dhcp', '--config-file',
                    base.etcdir('neutron.conf')
                ]
                with mock.patch.object(sys, 'argv', test_args):
                    cfg.CONF.register_opts(dhcp_config.DHCP_AGENT_OPTS)
                    config.register_interface_driver_opts_helper(cfg.CONF)
                    config.register_agent_state_opts_helper(cfg.CONF)
                    config.register_interface_opts(cfg.CONF)
                    common_config.init(sys.argv[1:])
                    agent_mgr = dhcp_agent.DhcpAgentWithStateReport(
                        'testhost')
                    eventlet.greenthread.sleep(1)
                    agent_mgr.after_start()
                    mock_periodic_resync.assert_called_once_with(agent_mgr)
                    mock_start_ready.assert_called_once_with(agent_mgr)
                    state_rpc.assert_has_calls(
                        [mock.call(mock.ANY),
                         mock.call().report_state(mock.ANY, mock.ANY,
                                                  mock.ANY)])

    def test_run_completes_single_pass(self):
        with mock.patch(DEVICE_MANAGER):
            dhcp = dhcp_agent.DhcpAgent(HOSTNAME)
            attrs_to_mock = dict(
                (a, mock.DEFAULT) for a in
                ['periodic_resync', 'start_ready_ports_loop',
                 '_process_loop'])
            with mock.patch.multiple(dhcp, **attrs_to_mock) as mocks:
                with mock.patch.object(dhcp_agent.eventlet,
                                       'spawn_n') as spawn_n:
                    dhcp.run()
                    mocks['periodic_resync'].assert_called_once_with()
                    mocks['start_ready_ports_loop'].assert_called_once_with()
                    spawn_n.assert_called_once_with(mocks['_process_loop'])

    def test_call_driver(self):
        network = mock.MagicMock()
        network.id = '1'
        network.segments = None
        dhcp = dhcp_agent.DhcpAgent(cfg.CONF)
        self.assertTrue(dhcp.call_driver('foo', network))
        self.driver.assert_called_once_with(cfg.CONF,
                                            mock.ANY,
                                            mock.ANY,
                                            mock.ANY,
                                            mock.ANY,
                                            None)

    def test_call_driver_no_network(self):
        network = None
        dhcp = dhcp_agent.DhcpAgent(cfg.CONF)
        self.assertIsNone(dhcp.call_driver('foo', network))

    def _test_call_driver_failure(self, exc=None,
                                  trace_level='exception', expected_sync=True):
        network = mock.MagicMock()
        network.id = '1'
        network.segments = None
        self.driver.return_value.foo.side_effect = exc or Exception
        dhcp = dhcp_agent.DhcpAgent(HOSTNAME)
        with mock.patch.object(dhcp,
                               'schedule_resync') as schedule_resync:
            self.assertIsNone(dhcp.call_driver('foo', network))
            self.driver.assert_called_once_with(cfg.CONF,
                                                mock.ANY,
                                                mock.ANY,
                                                mock.ANY,
                                                mock.ANY,
                                                None)
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

    def test_call_driver_get_metadata_bind_interface_returns(self):
        network = mock.MagicMock()
        network.segments = None
        self.driver().get_metadata_bind_interface.return_value = 'iface0'
        agent = dhcp_agent.DhcpAgent(cfg.CONF)
        self.assertEqual(
            'iface0',
            agent.call_driver('get_metadata_bind_interface', network))

    def _test_sync_state_helper(self, known_net_ids, active_net_ids):
        active_networks = set(mock.Mock(id=netid) for netid in active_net_ids)

        with mock.patch(DHCP_PLUGIN) as plug:
            mock_plugin = mock.Mock()
            mock_plugin.get_active_networks_info.return_value = active_networks
            plug.return_value = mock_plugin

            dhcp = dhcp_agent.DhcpAgent(HOSTNAME)

            attrs_to_mock = dict((a, mock.DEFAULT)
                                 for a in ['disable_dhcp_helper', 'cache',
                                           'safe_configure_dhcp_for_network'])

            with mock.patch.multiple(dhcp, **attrs_to_mock) as mocks:
                mocks['cache'].get_network_ids.return_value = known_net_ids
                mocks['cache'].get_port_ids.return_value = range(4)
                dhcp.sync_state()

                diff = set(known_net_ids) - set(active_net_ids)
                exp_disable = [mock.call(net_id) for net_id in diff]
                mocks['cache'].assert_has_calls([mock.call.get_network_ids()])
                mocks['disable_dhcp_helper'].assert_has_calls(exp_disable)
                self.assertEqual(set(range(4)), dhcp.dhcp_ready_ports)

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

    def test_sync_state_for_all_networks_plugin_error(self):
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

    def test_sync_state_for_one_network_plugin_error(self):
        with mock.patch(DHCP_PLUGIN) as plug:
            mock_plugin = mock.Mock()
            exc = Exception()
            mock_plugin.get_active_networks_info.side_effect = exc
            plug.return_value = mock_plugin

            with mock.patch.object(dhcp_agent.LOG, 'exception') as log:
                dhcp = dhcp_agent.DhcpAgent(HOSTNAME)
                with mock.patch.object(dhcp,
                                       'schedule_resync') as schedule_resync:
                    dhcp.sync_state(['foo_network'])

                    self.assertTrue(log.called)
                    schedule_resync.assert_called_with(exc, 'foo_network')

    def test_periodic_resync(self):
        dhcp = dhcp_agent.DhcpAgent(HOSTNAME)
        with mock.patch.object(dhcp_agent.eventlet, 'spawn') as spawn:
            dhcp.periodic_resync()
            spawn.assert_called_once_with(dhcp._periodic_resync_helper)

    def test_start_ready_ports_loop(self):
        dhcp = dhcp_agent.DhcpAgent(HOSTNAME)
        with mock.patch.object(dhcp_agent.eventlet, 'spawn') as spawn:
            dhcp.start_ready_ports_loop()
            spawn.assert_called_once_with(dhcp._dhcp_ready_ports_loop)

    def test__dhcp_ready_ports_doesnt_log_exception_on_timeout(self):
        dhcp = dhcp_agent.DhcpAgent(HOSTNAME)
        dhcp.dhcp_ready_ports = set(range(4))

        with mock.patch.object(dhcp.plugin_rpc, 'dhcp_ready_on_ports',
                               side_effect=oslo_messaging.MessagingTimeout):
            # exit after 2 iterations
            with mock.patch.object(dhcp_agent.eventlet, 'sleep',
                                   side_effect=[0, 0, RuntimeError]):
                with mock.patch.object(dhcp_agent.LOG, 'exception') as lex:
                    with testtools.ExpectedException(RuntimeError):
                        dhcp._dhcp_ready_ports_loop()
        self.assertFalse(lex.called)

    def test__dhcp_ready_ports_loop(self):
        dhcp = dhcp_agent.DhcpAgent(HOSTNAME)
        dhcp.dhcp_ready_ports = set(range(4))

        with mock.patch.object(dhcp.plugin_rpc, 'dhcp_ready_on_ports',
                               side_effect=[RuntimeError, 0]) as ready:
            # exit after 2 iterations
            with mock.patch.object(dhcp_agent.eventlet, 'sleep',
                                   side_effect=[0, 0, RuntimeError]):
                with testtools.ExpectedException(RuntimeError):
                    dhcp._dhcp_ready_ports_loop()
        # should have been called with all ports again after the failure
        ready.assert_has_calls([mock.call(set(range(4)))] * 2)

    def test_dhcp_ready_ports_loop_with_limit_ports_per_call(self):
        dhcp = dhcp_agent.DhcpAgent(HOSTNAME)
        sync_max = dhcp_agent.DHCP_READY_PORTS_SYNC_MAX
        port_count = sync_max + 1
        dhcp.dhcp_ready_ports = set(range(port_count))

        with mock.patch.object(dhcp.plugin_rpc,
                               'dhcp_ready_on_ports') as ready:
            # exit after 2 iterations
            with mock.patch.object(dhcp_agent.eventlet, 'sleep',
                                   side_effect=[0, 0, RuntimeError]):
                with testtools.ExpectedException(RuntimeError):
                    dhcp._dhcp_ready_ports_loop()

        # all ports should have been processed
        self.assertEqual(set(), dhcp.dhcp_ready_ports)
        # two calls are expected, one with DHCP_READY_PORTS_SYNC_MAX ports,
        # second one with one port
        self.assertEqual(2, ready.call_count)
        self.assertEqual(sync_max, len(ready.call_args_list[0][0][0]))
        self.assertEqual(1, len(ready.call_args_list[1][0][0]))
        # all ports need to be ready
        ports_ready = (ready.call_args_list[0][0][0] |
                       ready.call_args_list[1][0][0])
        self.assertEqual(set(range(port_count)), ports_ready)

    def test_dhcp_ready_ports_loop_with_limit_ports_per_call_prio(self):
        dhcp = dhcp_agent.DhcpAgent(HOSTNAME)
        sync_max = dhcp_agent.DHCP_READY_PORTS_SYNC_MAX
        port_count = 4
        # port set ranges must be unique to differentiate results
        dhcp.dhcp_prio_ready_ports = set(range(sync_max))
        dhcp.dhcp_ready_ports = set(range(sync_max, sync_max + port_count))

        with mock.patch.object(dhcp.plugin_rpc,
                               'dhcp_ready_on_ports') as ready:
            # exit after 1 iteration
            with mock.patch.object(dhcp_agent.eventlet, 'sleep',
                                   side_effect=[0, RuntimeError]):
                with testtools.ExpectedException(RuntimeError):
                    dhcp._dhcp_ready_ports_loop()

        # only priority ports should have been processed
        self.assertEqual(set(), dhcp.dhcp_prio_ready_ports)
        self.assertEqual(set(range(sync_max, sync_max + port_count)),
                         dhcp.dhcp_ready_ports)
        # one call is expected, with DHCP_READY_PORTS_SYNC_MAX ports
        ready.assert_called_once()
        self.assertEqual(sync_max, len(ready.call_args_list[0][0][0]))
        # priority ports need to be ready
        ports_ready = ready.call_args_list[0][0][0]
        self.assertEqual(set(range(sync_max)), ports_ready)

        # add some priority ports, to make sure they are processed
        dhcp.dhcp_prio_ready_ports = set(range(port_count))
        with mock.patch.object(dhcp.plugin_rpc,
                               'dhcp_ready_on_ports') as ready:
            # exit after 1 iteration
            with mock.patch.object(dhcp_agent.eventlet, 'sleep',
                                   side_effect=[0, RuntimeError]):
                with testtools.ExpectedException(RuntimeError):
                    dhcp._dhcp_ready_ports_loop()

        # all ports should have been processed
        self.assertEqual(set(), dhcp.dhcp_prio_ready_ports)
        self.assertEqual(set(), dhcp.dhcp_ready_ports)
        # one call is expected, with (port_count * 2) ports
        ready.assert_called_once()
        self.assertEqual(port_count * 2, len(ready.call_args_list[0][0][0]))
        # all ports need to be ready
        ports_ready = ready.call_args_list[0][0][0]
        all_ports = (set(range(port_count)) |
                     set(range(sync_max, sync_max + port_count)))
        self.assertEqual(all_ports, ports_ready)

    def test_configure_dhcp_for_network(self):
        dhcp = dhcp_agent.DhcpAgent(HOSTNAME)
        with mock.patch.object(
                dhcp, 'update_isolated_metadata_proxy') as ump, \
            mock.patch.object(
                dhcp, 'call_driver', return_value=True):
            dhcp.configure_dhcp_for_network(fake_network)

        ump.assert_called_once_with(fake_network)
        self.assertIn(fake_network.id, dhcp.cache.get_network_ids())
        self.assertIn(fake_port1.id, dhcp.dhcp_ready_ports)

    def test_configure_dhcp_for_network_no_subnets_with_dhcp_enabled(self):
        dhcp = dhcp_agent.DhcpAgent(HOSTNAME)
        with mock.patch.object(
                dhcp, 'update_isolated_metadata_proxy') as ump, \
            mock.patch.object(
                dhcp, 'call_driver', return_value=True) as call_driver_mock:
            dhcp.configure_dhcp_for_network(fake_network_no_dhcp_subnets)

        ump.assert_not_called()
        call_driver_mock.assert_not_called()
        self.assertNotIn(fake_network_no_dhcp_subnets.id,
                         dhcp.cache.get_network_ids())
        self.assertNotIn(fake_port_subnet_2.id, dhcp.dhcp_ready_ports)

    @mock.patch.object(linux_utils, 'delete_if_exists')
    def test_dhcp_ready_ports_updates_after_enable_dhcp(self, *args):
        with mock.patch('neutron.agent.linux.ip_lib.'
                        'IpAddrCommand.wait_until_address_ready') as mock_wait:
            mock_wait.return_value = True
            dhcp = dhcp_agent.DhcpAgent(HOSTNAME)
            self.assertEqual(set(), dhcp.dhcp_ready_ports)
            dhcp.configure_dhcp_for_network(fake_network)
            self.assertEqual({fake_port1.id}, dhcp.dhcp_ready_ports)

    def test_dhcp_metadata_destroy(self):
        cfg.CONF.set_override('force_metadata', True)
        cfg.CONF.set_override('enable_isolated_metadata', False)

        with mock.patch.object(metadata_driver,
                               'MetadataDriver') as md_cls:
            dhcp = dhcp_agent.DhcpAgent(HOSTNAME)
            dhcp.configure_dhcp_for_network(fake_network)
            md_cls.spawn_monitored_metadata_proxy.assert_called_once_with(
                mock.ANY, mock.ANY, mock.ANY, mock.ANY,
                bind_address=const.METADATA_V4_IP,
                network_id=fake_network.id)
            md_cls.reset_mock()
            dhcp.disable_dhcp_helper(fake_network.id)
            md_cls.destroy_monitored_metadata_proxy.assert_called_once_with(
                mock.ANY, fake_network.id, mock.ANY, fake_network.namespace)

    def test_agent_start_restarts_metadata_proxy(self):
        cfg.CONF.set_override('force_metadata', True)
        cfg.CONF.set_override('enable_isolated_metadata', False)

        with mock.patch.object(metadata_driver,
                               'MetadataDriver') as md_cls:
            dhcp = dhcp_agent.DhcpAgent(HOSTNAME)
            dhcp.configure_dhcp_for_network(fake_network)
            md_cls.destroy_monitored_metadata_proxy.assert_called_once_with(
                mock.ANY, fake_network.id, mock.ANY, fake_network.namespace)
            md_cls.spawn_monitored_metadata_proxy.assert_called_once_with(
                mock.ANY, mock.ANY, mock.ANY, mock.ANY,
                bind_address=const.METADATA_V4_IP,
                network_id=fake_network.id)

    def test_report_state_revival_logic(self):
        dhcp = dhcp_agent.DhcpAgentWithStateReport(HOSTNAME)
        with mock.patch.object(dhcp.state_rpc,
                               'report_state') as report_state,\
                mock.patch.object(dhcp, "run"):
            report_state.return_value = agent_consts.AGENT_ALIVE
            dhcp._report_state()
            self.assertEqual({}, dhcp.needs_resync_reasons)

            report_state.return_value = agent_consts.AGENT_REVIVED
            dhcp._report_state()
            self.assertEqual(dhcp.needs_resync_reasons[None],
                             ['Agent has just been revived'])

    def test_periodic_resync_helper(self):
        dhcp = dhcp_agent.DhcpAgent(HOSTNAME)
        resync_reasons = collections.OrderedDict(
            (('a', 'reason1'), ('b', 'reason2')))
        dhcp.needs_resync_reasons = resync_reasons
        with mock.patch.object(dhcp, 'sync_state') as sync_state:
            sync_state.side_effect = RuntimeError
            with testtools.ExpectedException(RuntimeError):
                dhcp._periodic_resync_helper()
            sync_state.assert_called_once_with(list(resync_reasons.keys()))
            self.assertEqual(0, len(dhcp.needs_resync_reasons))

    def test_periodic_resync_helper_with_event(self):
        with mock.patch.object(dhcp_agent.LOG, 'debug') as log:
            dhcp = dhcp_agent.DhcpAgent(HOSTNAME)
            dhcp.schedule_resync('reason1', 'a')
            dhcp.schedule_resync('reason1', 'b')
            reasons = list(dhcp.needs_resync_reasons.keys())
            with mock.patch.object(dhcp, 'sync_state') as sync_state:
                sync_state.side_effect = RuntimeError
                with testtools.ExpectedException(RuntimeError):
                    dhcp._periodic_resync_helper()
            log.assert_any_call("Resync event has been scheduled")
            sync_state.assert_called_once_with(reasons)
            self.assertEqual(0, len(dhcp.needs_resync_reasons))

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
                          cfg.CONF, mock.Mock())

    def test_nonexistent_interface_driver(self):
        # Temporarily turn off mock, so could use the real import_class
        # to import interface_driver.
        self.driver_cls_p.stop()
        self.addCleanup(self.driver_cls_p.start)
        cfg.CONF.set_override('interface_driver', 'foo.bar')
        self.assertRaises(SystemExit, dhcp.DeviceManager,
                          cfg.CONF, mock.Mock())


class TestDhcpAgentEventHandler(base.BaseTestCase):
    def setUp(self):
        super(TestDhcpAgentEventHandler, self).setUp()
        config.register_interface_driver_opts_helper(cfg.CONF)
        cfg.CONF.set_override('interface_driver',
                              'neutron.agent.linux.interface.NullDriver')
        entry.register_options(cfg.CONF)  # register all dhcp cfg options

        self.plugin_p = mock.patch(DHCP_PLUGIN)
        plugin_cls = self.plugin_p.start()
        self.plugin = mock.Mock()
        plugin_cls.return_value = self.plugin

        self.cache_p = mock.patch('neutron.agent.dhcp.agent.NetworkCache')
        cache_cls = self.cache_p.start()
        self.cache = mock.Mock()
        self.cache.is_port_message_stale.return_value = False
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
        self.mock_resize_p = mock.patch('neutron.agent.dhcp.agent.'
                                        'DhcpAgent._resize_process_pool')
        self.mock_resize = self.mock_resize_p.start()
        self.mock_wait_until_address_ready_p = mock.patch(
            'neutron.agent.linux.ip_lib.'
            'IpAddrCommand.wait_until_address_ready')
        self.mock_wait_until_address_ready_p.start()
        mock.patch.object(linux_utils, 'delete_if_exists').start()
        self.addCleanup(self.mock_wait_until_address_ready_p.stop)

    def _process_manager_constructor_call(self, ns=FAKE_NETWORK_DHCP_NS):
        return mock.call(conf=cfg.CONF,
                         uuid=FAKE_NETWORK_UUID,
                         namespace=ns,
                         service='haproxy',
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
        if is_isolated_network and enable_isolated_metadata:
            self.external_process.assert_has_calls([
                self._process_manager_constructor_call(),
                mock.call().enable()], any_order=True)
        else:
            self.external_process.assert_has_calls([
                self._process_manager_constructor_call(),
                mock.call().disable(sig=str(int(signal.SIGTERM)))])

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
        nonisolated_dvr_network = copy.deepcopy(nonisolated_dist_network)
        nonisolated_dvr_network.ports[0].device_owner = (
            const.DEVICE_OWNER_ROUTER_INTF)
        nonisolated_dvr_network.ports[0].fixed_ips[0].ip_address = '172.9.9.1'
        nonisolated_dvr_network.ports[1].device_owner = (
            const.DEVICE_OWNER_DVR_INTERFACE)
        nonisolated_dvr_network.ports[1].fixed_ips[0].ip_address = '172.9.9.1'

        self._enable_dhcp_helper(nonisolated_dvr_network,
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
        with mock.patch.object(self.dhcp,
                'enable_isolated_metadata_proxy') as enable_metadata:
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
        self.dhcp.enable_dhcp_helper('fake_id')
        self.plugin.assert_has_calls(
            [mock.call.get_network_info('fake_id')])
        self.assertFalse(self.call_driver.called)
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
        cfg.CONF.set_override('enable_isolated_metadata', True)
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
        self.external_process.assert_has_calls([
            self._process_manager_constructor_call(),
            mock.call().disable(sig=str(int(signal.SIGTERM)))])

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
        self.external_process.assert_has_calls([
            self._process_manager_constructor_call(),
            mock.call().disable(sig=str(int(signal.SIGTERM)))
        ])

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
        ], any_order=True)

    def test_disable_isolated_metadata_proxy(self):
        method_path = ('neutron.agent.metadata.driver.MetadataDriver'
                       '.destroy_monitored_metadata_proxy')
        with mock.patch(method_path) as destroy:
            self.dhcp.disable_isolated_metadata_proxy(fake_network)
            destroy.assert_called_once_with(self.dhcp._process_monitor,
                                            fake_network.id,
                                            cfg.CONF,
                                            fake_network.namespace)

    def _test_enable_isolated_metadata_proxy(self, network):
        cfg.CONF.set_override('enable_metadata_network', True)
        cfg.CONF.set_override('debug', True)
        cfg.CONF.set_override('log_file', 'test.log')
        method_path = ('neutron.agent.metadata.driver.MetadataDriver'
                       '.spawn_monitored_metadata_proxy')
        with mock.patch(method_path) as spawn:
            self.dhcp.enable_isolated_metadata_proxy(network)
            metadata_ip = const.METADATA_V4_IP
            spawn.assert_called_once_with(self.dhcp._process_monitor,
                                          network.namespace,
                                          const.METADATA_PORT,
                                          cfg.CONF,
                                          bind_address=metadata_ip,
                                          router_id='forzanapoli')

    def test_enable_isolated_metadata_proxy_with_metadata_network(self):
        self._test_enable_isolated_metadata_proxy(fake_meta_network)

    def test_enable_isolated_metadata_proxy_with_metadata_network_dvr(self):
        self._test_enable_isolated_metadata_proxy(fake_meta_dvr_network)

    def test_enable_isolated_metadata_proxy_with_dist_network(self):
        self._test_enable_isolated_metadata_proxy(fake_dist_network)

    def _test_enable_isolated_metadata_proxy_ipv6(self, network):
        cfg.CONF.set_override('enable_metadata_network', True)
        cfg.CONF.set_override('debug', True)
        cfg.CONF.set_override('log_file', 'test.log')
        method_path = ('neutron.agent.metadata.driver.MetadataDriver'
                       '.spawn_monitored_metadata_proxy')
        with mock.patch(method_path) as spawn, \
                mock.patch.object(netutils, 'is_ipv6_enabled') as mock_ipv6:
            mock_ipv6.return_value = True
            self.call_driver.return_value = 'fake-interface'
            self.dhcp.enable_isolated_metadata_proxy(network)
            spawn.assert_called_once_with(self.dhcp._process_monitor,
                                          network.namespace,
                                          const.METADATA_PORT,
                                          cfg.CONF,
                                          bind_address='169.254.169.254',
                                          network_id=network.id,
                                          bind_interface='fake-interface',
                                          bind_address_v6='fe80::a9fe:a9fe')

    def test_enable_isolated_metadata_proxy_with_metadata_network_ipv6(self):
        network = copy.deepcopy(fake_meta_network)
        dhcp_port_this_host = copy.deepcopy(fake_dhcp_port)
        dhcp_port_this_host.device_id = utils.get_dhcp_agent_device_id(
            network.id, self.dhcp.conf.host)
        network.ports = [dhcp_port_this_host]
        self._test_enable_isolated_metadata_proxy_ipv6(network)

    def test_enable_isolated_metadata_proxy_with_metadata_network_dvr_ipv6(
            self):
        network = copy.deepcopy(fake_meta_dvr_network)
        dhcp_port_this_host = copy.deepcopy(fake_dhcp_port)
        dhcp_port_this_host.device_id = utils.get_dhcp_agent_device_id(
            network.id, self.dhcp.conf.host)
        network.ports = [dhcp_port_this_host]
        self._test_enable_isolated_metadata_proxy_ipv6(network)

    def test_enable_isolated_metadata_proxy_with_dist_network_ipv6(self):
        network = copy.deepcopy(fake_dist_network)
        dhcp_port_this_host = copy.deepcopy(fake_dhcp_port)
        dhcp_port_this_host.device_id = utils.get_dhcp_agent_device_id(
            network.id, self.dhcp.conf.host)
        network.ports = [dhcp_port_this_host]
        self._test_enable_isolated_metadata_proxy_ipv6(network)

    def test_enable_isolated_metadata_proxy_with_2_agents_network_ipv6(self):
        network = copy.deepcopy(fake_meta_network)
        dhcp_port_this_host = copy.deepcopy(fake_dhcp_port)
        dhcp_port_this_host.device_id = utils.get_dhcp_agent_device_id(
            network.id, self.dhcp.conf.host)
        dhcp_port_other_host = copy.deepcopy(fake_dhcp_port)
        dhcp_port_other_host.device_id = utils.get_dhcp_agent_device_id(
            network.id, 'otherhostname')
        network.ports = [dhcp_port_this_host, dhcp_port_other_host]
        self._test_enable_isolated_metadata_proxy_ipv6(network)

    def _test_disable_isolated_metadata_proxy(self, network):
        cfg.CONF.set_override('enable_metadata_network', True)
        method_path = ('neutron.agent.metadata.driver.MetadataDriver'
                       '.destroy_monitored_metadata_proxy')
        with mock.patch(method_path) as destroy:
            self.dhcp.enable_isolated_metadata_proxy(network)
            self.dhcp.disable_isolated_metadata_proxy(network)
            destroy.assert_called_once_with(self.dhcp._process_monitor,
                                            'forzanapoli',
                                            cfg.CONF,
                                            network.namespace)

    def test_disable_isolated_metadata_proxy_with_metadata_network(self):
        self._test_disable_isolated_metadata_proxy(fake_meta_network)

    def test_disable_isolated_metadata_proxy_with_metadata_network_dvr(self):
        self._test_disable_isolated_metadata_proxy(fake_meta_dvr_network)

    def test_disable_isolated_metadata_proxy_with_dist_network(self):
        self._test_disable_isolated_metadata_proxy(fake_dist_network)

    def test_network_create_end(self):
        payload = dict(network=dict(id=fake_network.id),
                       priority=FAKE_PRIORITY)

        with mock.patch.object(self.dhcp, 'enable_dhcp_helper') as enable:
            self.dhcp.network_create_end(None, payload)
            self.dhcp._process_resource_update()
            enable.assert_called_once_with(fake_network.id)

    def test_network_update_end_admin_state_up(self):
        payload = dict(network=dict(id=fake_network.id, admin_state_up=True),
                       priority=FAKE_PRIORITY)
        with mock.patch.object(self.dhcp, 'enable_dhcp_helper') as enable:
            self.dhcp.network_update_end(None, payload)
            self.dhcp._process_resource_update()
            enable.assert_called_once_with(fake_network.id)

    def test_network_update_end_admin_state_down(self):
        payload = dict(network=dict(id=fake_network.id, admin_state_up=False),
                       priority=FAKE_PRIORITY)
        with mock.patch.object(self.dhcp, 'disable_dhcp_helper') as disable:
            self.dhcp.network_update_end(None, payload)
            self.dhcp._process_resource_update()
            disable.assert_called_once_with(fake_network.id)

    def test_network_delete_end(self):
        payload = dict(network_id=fake_network.id, priority=FAKE_PRIORITY)

        with mock.patch.object(self.dhcp, 'disable_dhcp_helper') as disable:
            self.dhcp.network_delete_end(None, payload)
            self.dhcp._process_resource_update()
            disable.assert_called_once_with(fake_network.id)

    def test_refresh_dhcp_helper_no_dhcp_enabled_networks(self):
        network = dhcp.NetModel(dict(id='net-id',
                                     project_id=FAKE_PROJECT_ID,
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
        network = dhcp.NetModel(dict(id='net-id',
                                     project_id=FAKE_PROJECT_ID,
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

    def test_subnet_create_end(self):
        # We should call reload_allocations when subnet's enable_dhcp
        # attribute isn't True.
        payload = dict(subnet=dhcp.DictModel(
              dict(network_id=fake_network.id, enable_dhcp=False,
                   cidr='99.99.99.0/24', ip_version=const.IP_VERSION_4)),
                   priority=FAKE_PRIORITY)
        self.cache.get_network_by_id.return_value = fake_network
        new_net = copy.deepcopy(fake_network)
        new_net.subnets.append(payload['subnet'])
        self.plugin.get_network_info.return_value = new_net

        self.dhcp.subnet_create_end(None, payload)
        self.dhcp._process_resource_update()

        self.cache.assert_has_calls([mock.call.put(new_net)])
        self.call_driver.assert_called_once_with('reload_allocations', new_net)

        # We should call restart when subnet's enable_dhcp attribute is True.
        self.call_driver.reset_mock()
        payload = dict(subnet=dhcp.DictModel(
              dict(network_id=fake_network.id, enable_dhcp=True,
                   cidr='99.99.88.0/24', ip_version=const.IP_VERSION_4)),
              priority=FAKE_PRIORITY)
        new_net = copy.deepcopy(fake_network)
        new_net.subnets.append(payload['subnet'])
        self.plugin.get_network_info.return_value = new_net
        self.dhcp.subnet_create_end(None, payload)
        self.dhcp._process_resource_update()
        self.cache.assert_has_calls([mock.call.put(new_net)])
        self.call_driver.assert_called_once_with('restart', new_net)

    def test_subnet_update_end(self):
        payload = dict(subnet=dict(network_id=fake_network.id),
                       priority=FAKE_PRIORITY)
        self.cache.get_network_by_id.return_value = fake_network
        self.plugin.get_network_info.return_value = fake_network

        self.dhcp.subnet_update_end(None, payload)
        self.dhcp._process_resource_update()

        self.cache.assert_has_calls([mock.call.put(fake_network)])
        self.call_driver.assert_called_once_with('reload_allocations',
                                                 fake_network)
        # ensure all ports flagged as ready
        self.assertEqual({p.id for p in fake_network.ports},
                         self.dhcp.dhcp_ready_ports)

    def test_subnet_update_dhcp(self):
        payload = dict(subnet=dict(network_id=fake_network.id),
                       priority=FAKE_PRIORITY)
        self.cache.get_network_by_id.return_value = fake_network
        new_net = copy.deepcopy(fake_network)
        new_subnet1 = copy.deepcopy(fake_subnet1)
        new_subnet2 = copy.deepcopy(fake_subnet2)
        new_subnet2.enable_dhcp = True
        new_net.subnets = [new_subnet1, new_subnet2]
        self.plugin.get_network_info.return_value = new_net
        self.dhcp.subnet_update_end(None, payload)
        self.dhcp._process_resource_update()
        self.call_driver.assert_called_once_with('restart', new_net)

        self.call_driver.reset_mock()
        self.cache.get_network_by_id.return_value = new_net
        new_net2 = copy.deepcopy(new_net)
        new_subnet1 = copy.deepcopy(new_subnet1)
        new_subnet1.enable_dhcp = False
        new_subnet2 = copy.deepcopy(new_subnet2)
        new_net2.subnets = [new_subnet1, new_subnet2]
        self.plugin.get_network_info.return_value = new_net2
        self.dhcp.subnet_update_end(None, payload)
        self.dhcp._process_resource_update()
        self.call_driver.assert_called_once_with('restart', new_net2)

    def test_subnet_update_end_restart(self):
        new_state = dhcp.NetModel(dict(id=fake_network.id,
                                       project_id=fake_network.project_id,
                                       admin_state_up=True,
                                       subnets=[fake_subnet1, fake_subnet3],
                                       ports=[fake_port1]))

        payload = dict(subnet=dict(network_id=fake_network.id),
                       priority=FAKE_PRIORITY)
        self.cache.get_network_by_id.return_value = fake_network
        self.plugin.get_network_info.return_value = new_state

        self.dhcp.subnet_update_end(None, payload)
        self.dhcp._process_resource_update()

        self.cache.assert_has_calls([mock.call.put(new_state)])
        self.call_driver.assert_called_once_with('restart',
                                                 new_state)

    def test_subnet_delete_end_no_network_id(self):
        prev_state = dhcp.NetModel(dict(id=fake_network.id,
                                        project_id=fake_network.project_id,
                                        admin_state_up=True,
                                        subnets=[fake_subnet1, fake_subnet3],
                                        ports=[fake_port1]))

        payload = {'subnet_id': fake_subnet1.id, 'priority': FAKE_PRIORITY,
                   'network_id': fake_network.id}
        self.cache.get_network_by_subnet_id.return_value = prev_state
        self.cache.get_network_by_id.return_value = prev_state
        self.plugin.get_network_info.return_value = fake_network

        self.dhcp.subnet_delete_end(None, payload)
        self.dhcp._process_resource_update()

        self.cache.assert_has_calls([
            mock.call.get_network_by_subnet_id(
                'bbbbbbbb-bbbb-bbbb-bbbbbbbbbbbb'),
            mock.call.get_network_by_id('12345678-1234-5678-1234567890ab'),
            mock.call.put(fake_network)])
        self.call_driver.assert_called_once_with('restart',
                                                 fake_network)

    def test_subnet_update_end_delete_payload(self):
        prev_state = dhcp.NetModel(dict(id=fake_network.id,
                                        project_id=fake_network.project_id,
                                        admin_state_up=True,
                                        subnets=[fake_subnet1, fake_subnet3],
                                        ports=[fake_port1]))

        payload = dict(subnet_id=fake_subnet1.id, network_id=fake_network.id,
                       priority=FAKE_PRIORITY)
        self.cache.get_network_by_subnet_id.return_value = prev_state
        self.cache.get_network_by_id.return_value = prev_state
        self.plugin.get_network_info.return_value = fake_network

        self.dhcp.subnet_delete_end(None, payload)
        self.dhcp._process_resource_update()

        self.cache.assert_has_calls([
            mock.call.get_network_by_subnet_id(
                'bbbbbbbb-bbbb-bbbb-bbbbbbbbbbbb'),
            mock.call.get_network_by_id(FAKE_NETWORK_UUID),
            mock.call.put(fake_network)])
        self.call_driver.assert_called_once_with('restart',
                                                 fake_network)

    def test_port_update_end(self):
        self.reload_allocations_p = mock.patch.object(self.dhcp,
                                                      'reload_allocations')
        self.reload_allocations = self.reload_allocations_p.start()
        payload = dict(port=copy.deepcopy(fake_port2))
        self.cache.get_network_by_id.return_value = fake_network
        self.dhcp.port_update_end(None, payload)
        self.dhcp._process_resource_update()
        self.reload_allocations.assert_called_once_with(fake_port2,
                                                        fake_network,
                                                        prio=True)

    def test_reload_allocations(self):
        self.cache.get_port_by_id.return_value = fake_port2
        with mock.patch.object(
                self.dhcp, 'update_isolated_metadata_proxy') as ump:
            self.dhcp.reload_allocations(fake_port2, fake_network)
            self.cache.assert_has_calls([mock.call.put_port(mock.ANY)])
            self.call_driver.assert_called_once_with('reload_allocations',
                                                     fake_network)
            self.assertTrue(ump.called)

    def test_port_create_end(self):
        self.reload_allocations_p = mock.patch.object(self.dhcp,
                                                      'reload_allocations')
        self.reload_allocations = self.reload_allocations_p.start()
        payload = dict(port=copy.deepcopy(fake_port2))
        self.cache.get_network_by_id.return_value = fake_network
        self.dhcp.port_create_end(None, payload)
        self.dhcp._process_resource_update()
        self.reload_allocations.assert_called_once_with(fake_port2,
                                                        fake_network,
                                                        prio=True)

    def test_port_create_end_no_resync_if_same_port_already_in_cache(self):
        self.reload_allocations_p = mock.patch.object(self.dhcp,
                                                      'reload_allocations')
        self.reload_allocations = self.reload_allocations_p.start()
        payload = dict(port=copy.deepcopy(fake_port2))
        cached_port = copy.deepcopy(fake_port2)
        new_fake_network = copy.deepcopy(fake_network)
        new_fake_network.ports = [cached_port]
        self.cache.get_network_by_id.return_value = new_fake_network
        self.dhcp.port_create_end(None, payload)
        self.dhcp._process_resource_update()
        self.reload_allocations.assert_called_once_with(fake_port2,
                                                        new_fake_network,
                                                        prio=True)
        self.schedule_resync.assert_not_called()

    def test_port_update_change_ip_on_port(self):
        payload = dict(port=fake_port1, priority=FAKE_PRIORITY)
        self.cache.get_network_by_id.return_value = fake_network
        updated_fake_port1 = copy.deepcopy(fake_port1)
        updated_fake_port1.fixed_ips[0].ip_address = '172.9.9.99'
        self.cache.get_port_by_id.return_value = updated_fake_port1
        with mock.patch.object(
                self.dhcp, 'update_isolated_metadata_proxy') as ump:
            self.dhcp.port_update_end(None, payload)
            self.dhcp._process_resource_update()
            self.cache.assert_has_calls(
                [mock.call.get_network_by_id(fake_port1.network_id),
                 mock.call.put_port(mock.ANY)])
            self.call_driver.assert_has_calls(
                [mock.call.call_driver('reload_allocations', fake_network)])
            self.assertTrue(ump.called)

    def test_port_update_change_subnet_on_dhcp_agents_port(self):
        self.cache.get_network_by_id.return_value = fake_network
        self.cache.get_port_by_id.return_value = fake_port1
        payload = dict(port=copy.deepcopy(fake_port1), priority=FAKE_PRIORITY)
        device_id = utils.get_dhcp_agent_device_id(
            payload['port']['network_id'], self.dhcp.conf.host)
        payload['port']['fixed_ips'][0]['subnet_id'] = '77777-7777'
        payload['port']['device_id'] = device_id
        self.dhcp.port_update_end(None, payload)
        self.dhcp._process_resource_update()
        self.assertFalse(self.call_driver.called)

    def test_port_update_change_ip_on_dhcp_agents_port(self):
        self.cache.get_network_by_id.return_value = fake_network
        self.cache.get_port_by_id.return_value = fake_port1
        payload = dict(port=copy.deepcopy(fake_port1), priority=FAKE_PRIORITY)
        device_id = utils.get_dhcp_agent_device_id(
            payload['port']['network_id'], self.dhcp.conf.host)
        payload['port']['fixed_ips'][0]['ip_address'] = '172.9.9.99'
        payload['port']['device_id'] = device_id
        self.dhcp.port_update_end(None, payload)
        self.dhcp._process_resource_update()
        self.call_driver.assert_has_calls(
            [mock.call.call_driver('restart', fake_network)])

    def test_port_update_change_ip_on_dhcp_agents_port_cache_miss(self):
        self.cache.get_network_by_id.return_value = fake_network
        self.cache.get_port_by_id.return_value = None
        payload = dict(port=copy.deepcopy(fake_port1), priority=FAKE_PRIORITY)
        device_id = utils.get_dhcp_agent_device_id(
            payload['port']['network_id'], self.dhcp.conf.host)
        payload['port']['fixed_ips'][0]['ip_address'] = '172.9.9.99'
        payload['port']['device_id'] = device_id
        self.dhcp.port_update_end(None, payload)
        self.dhcp._process_resource_update()
        self.schedule_resync.assert_called_once_with(mock.ANY,
                                                     fake_port1.network_id)

    def test_port_create_duplicate_ip_on_dhcp_agents_same_network(self):
        self.cache.get_network_by_id.return_value = fake_network
        payload = dict(port=copy.deepcopy(fake_port2))
        duplicate_ip = fake_port1['fixed_ips'][0]['ip_address']
        payload['port']['fixed_ips'][0]['ip_address'] = duplicate_ip
        self.dhcp.port_create_end(None, payload)
        self.dhcp._process_resource_update()
        self.schedule_resync.assert_called_once_with(mock.ANY,
                                                     fake_port2.network_id)

    def test_port_update_on_dhcp_agents_port_no_ip_change(self):
        self.cache.get_network_by_id.return_value = fake_network
        self.cache.get_port_by_id.return_value = fake_port1
        payload = dict(port=fake_port1, priority=FAKE_PRIORITY)
        device_id = utils.get_dhcp_agent_device_id(
            payload['port']['network_id'], self.dhcp.conf.host)
        payload['port']['device_id'] = device_id
        self.dhcp.port_update_end(None, payload)
        self.dhcp._process_resource_update()
        self.call_driver.assert_has_calls(
            [mock.call.call_driver('reload_allocations', fake_network)])

    def test_port_delete_end_no_network_id(self):
        payload = {'port_id': fake_port2.id, 'priority': FAKE_PRIORITY,
                   'network_id': fake_network.id}
        self.cache.get_network_by_id.return_value = fake_network
        self.cache.get_port_by_id.return_value = fake_port2

        with mock.patch.object(
                self.dhcp, 'update_isolated_metadata_proxy') as ump:
            self.dhcp.port_delete_end(None, payload)
            self.dhcp._process_resource_update()
            self.cache.assert_has_calls(
                [mock.call.get_port_by_id(fake_port2.id),
                 mock.call.get_network_by_id(fake_network.id),
                 mock.call.add_to_deleted_ports(fake_port2.id),
                 mock.call.remove_port(fake_port2)])
            self.call_driver.assert_has_calls(
                [mock.call.call_driver('reload_allocations', fake_network)])
            self.assertTrue(ump.called)

    def test_port_delete_network_already_deleted(self):
        port = dhcp.DictModel(copy.deepcopy(fake_port1))
        device_id = utils.get_dhcp_agent_device_id(
            port.network_id, self.dhcp.conf.host)
        port['device_id'] = device_id
        self.cache.get_network_by_id.return_value = None
        self.cache.get_port_by_id.return_value = port
        self.dhcp.port_delete_end(None, {'port_id': port.id,
          'network_id': fake_network.id,
          'priority': FAKE_PRIORITY})
        self.dhcp._process_resource_update()
        self.call_driver.assert_called_once_with(
            'disable', None, network_id=fake_network.id)

    def test_port_delete_end(self):
        payload = dict(port_id=fake_port2.id, network_id=fake_network.id,
                       priority=FAKE_PRIORITY)
        self.cache.get_network_by_id.return_value = fake_network
        self.cache.get_port_by_id.return_value = fake_port2

        with mock.patch.object(
                self.dhcp, 'update_isolated_metadata_proxy') as ump:
            self.dhcp.port_delete_end(None, payload)
            self.dhcp._process_resource_update()
            self.cache.assert_has_calls(
                [mock.call.get_port_by_id(fake_port2.id),
                 mock.call.get_network_by_id(fake_network.id),
                 mock.call.add_to_deleted_ports(fake_port2.id),
                 mock.call.remove_port(fake_port2)])
            self.call_driver.assert_has_calls(
                [mock.call.call_driver('reload_allocations', fake_network)])
            self.assertTrue(ump.called)

    def test_port_delete_end_unknown_port(self):
        payload = dict(port_id='unknown', network_id='unknown',
                       priority=FAKE_PRIORITY)
        self.cache.get_port_by_id.return_value = None
        self.cache.get_network_by_id.return_value = fake_network

        self.dhcp.port_delete_end(None, payload)
        self.dhcp._process_resource_update()

        self.cache.assert_has_calls([mock.call.get_port_by_id('unknown')])
        self.call_driver.assert_has_calls(
            [mock.call.call_driver('clean_devices', fake_network)])

    def test_port_delete_end_agents_port(self):
        port = dhcp.DictModel(copy.deepcopy(fake_port1))
        device_id = utils.get_dhcp_agent_device_id(
            port.network_id, self.dhcp.conf.host)
        port['device_id'] = device_id
        self.cache.get_network_by_id.return_value = fake_network
        self.cache.get_port_by_id.return_value = port
        self.dhcp.port_delete_end(None, {'port_id': port.id,
                                         'network_id': fake_network.id,
                                         'priority': FAKE_PRIORITY})
        self.dhcp._process_resource_update()
        self.call_driver.assert_has_calls(
            [mock.call.call_driver(
                'disable', fake_network, network_id=fake_network.id)])


class TestDhcpPluginApiProxy(base.BaseTestCase):
    def _test_dhcp_api(self, method, **kwargs):
        proxy = dhcp_agent.DhcpPluginApi('foo', host='foo')

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
            rpc_mock.assert_called_once_with(mock.ANY, method, **kwargs)

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


class TestNetworkCache(base.BaseTestCase):

    def setUp(self):
        super(TestNetworkCache, self).setUp()
        self.nc = dhcp_agent.NetworkCache()

    def test_update_of_deleted_port_ignored(self):
        self.nc.put(fake_network)
        self.nc.add_to_deleted_ports(fake_port2['id'])
        self.assertTrue(self.nc.is_port_message_stale(fake_port2))

    def test_stale_update_ignored(self):
        self.nc.put(fake_network)
        self.nc.put_port(fake_port2)
        stale = copy.copy(fake_port2)
        stale['revision_number'] = 2
        self.assertTrue(self.nc.is_port_message_stale(stale))

    def test_put_network(self):
        self.nc.put(fake_network)
        self.assertEqual(self.nc.cache,
                         {fake_network.id: fake_network})
        self.assertEqual(self.nc.subnet_lookup,
                         {fake_subnet1.id: fake_network.id,
                          fake_subnet2.id: fake_network.id})
        self.assertEqual(self.nc.port_lookup,
                         {fake_port1.id: fake_network.id})

    def test_put_network_existing(self):
        prev_network_info = mock.Mock()
        with mock.patch.object(self.nc, 'remove') as remove:
            self.nc.cache[fake_network.id] = prev_network_info

            self.nc.put(fake_network)
            remove.assert_called_once_with(prev_network_info)
        self.assertEqual(self.nc.cache,
                         {fake_network.id: fake_network})
        self.assertEqual(self.nc.subnet_lookup,
                         {fake_subnet1.id: fake_network.id,
                          fake_subnet2.id: fake_network.id})
        self.assertEqual(self.nc.port_lookup,
                         {fake_port1.id: fake_network.id})

    def test_remove_network(self):
        self.nc.cache = {fake_network.id: fake_network}
        self.nc.subnet_lookup = {fake_subnet1.id: fake_network.id,
                            fake_subnet2.id: fake_network.id}
        self.nc.port_lookup = {fake_port1.id: fake_network.id}
        self.nc.remove(fake_network)

        self.assertEqual(0, len(self.nc.cache))
        self.assertEqual(0, len(self.nc.subnet_lookup))
        self.assertEqual(0, len(self.nc.port_lookup))

    def test_get_network_by_id(self):
        self.nc.put(fake_network)
        self.assertEqual(self.nc.get_network_by_id(fake_network.id),
                         fake_network)

    def test_get_network_ids(self):
        self.nc.put(fake_network)
        self.assertEqual(list(self.nc.get_network_ids()), [fake_network.id])

    def test_get_network_by_subnet_id(self):
        self.nc.put(fake_network)
        self.assertEqual(self.nc.get_network_by_subnet_id(fake_subnet1.id),
                         fake_network)

    def test_get_network_by_port_id(self):
        self.nc.put(fake_network)
        self.assertEqual(self.nc.get_network_by_port_id(fake_port1.id),
                         fake_network)

    def test_get_port_ids(self):
        fake_net = dhcp.NetModel(
            dict(id=FAKE_NETWORK_UUID,
                 project_id=FAKE_PROJECT_ID,
                 subnets=[fake_subnet1],
                 ports=[fake_port1]))
        self.nc.put(fake_net)
        self.nc.put_port(fake_port2)
        self.assertEqual(set([fake_port1['id'], fake_port2['id']]),
                         set(self.nc.get_port_ids()))

    def test_get_port_ids_limited_nets(self):
        fake_net = dhcp.NetModel(
            dict(id=FAKE_NETWORK_UUID,
                 project_id=FAKE_PROJECT_ID,
                 subnets=[fake_subnet1],
                 ports=[fake_port1]))
        fake_port2 = copy.deepcopy(fake_port1)
        fake_port2['id'] = 'fp2'
        fake_port2['network_id'] = '12345678-1234-5678-1234567890ac'
        fake_net2 = dhcp.NetModel(
            dict(id='12345678-1234-5678-1234567890ac',
                 project_id=FAKE_PROJECT_ID,
                 subnets=[fake_subnet1],
                 ports=[fake_port2]))
        self.nc.put(fake_net)
        self.nc.put(fake_net2)
        self.assertEqual(set([fake_port1['id']]),
                         set(self.nc.get_port_ids([fake_net.id, 'net2'])))
        self.assertEqual(set(),
                         set(self.nc.get_port_ids(['net2'])))
        self.assertEqual(set([fake_port2['id']]),
                         set(self.nc.get_port_ids([fake_port2.network_id,
                                                   'net2'])))

    def test_put_port(self):
        fake_net = dhcp.NetModel(
            dict(id=FAKE_NETWORK_UUID,
                 project_id=FAKE_PROJECT_ID,
                 subnets=[fake_subnet1],
                 ports=[fake_port1]))
        self.nc.put(fake_net)
        self.nc.put_port(fake_port2)
        self.assertEqual(2, len(self.nc.port_lookup))
        self.assertIn(fake_port2, fake_net.ports)

    def test_put_port_existing(self):
        fake_net = dhcp.NetModel(
            dict(id=FAKE_NETWORK_UUID,
                 project_id=FAKE_PROJECT_ID,
                 subnets=[fake_subnet1],
                 ports=[fake_port1, fake_port2]))
        self.nc.put(fake_net)
        self.nc.put_port(fake_port2)

        self.assertEqual(2, len(self.nc.port_lookup))
        self.assertIn(fake_port2, fake_net.ports)

    def test_remove_port_existing(self):
        fake_net = dhcp.NetModel(
            dict(id=FAKE_NETWORK_UUID,
                 project_id=FAKE_PROJECT_ID,
                 subnets=[fake_subnet1],
                 ports=[fake_port1, fake_port2]))
        self.nc.put(fake_net)
        self.nc.remove_port(fake_port2)

        self.assertEqual(1, len(self.nc.port_lookup))
        self.assertNotIn(fake_port2, fake_net.ports)

    def test_get_port_by_id(self):
        self.nc.put(fake_network)
        self.assertEqual(self.nc.get_port_by_id(fake_port1.id), fake_port1)

    def _reset_deleted_port_max_age(self, old_value):
        dhcp_agent.DELETED_PORT_MAX_AGE = old_value

    def test_cleanup_deleted_ports(self):
        self.addCleanup(self._reset_deleted_port_max_age,
                        dhcp_agent.DELETED_PORT_MAX_AGE)
        dhcp_agent.DELETED_PORT_MAX_AGE = 10
        with mock.patch.object(timeutils, 'utcnow_ts') as mock_utcnow:
            mock_utcnow.side_effect = [1, 2, 11]
            self.nc.add_to_deleted_ports(fake_port1.id)
            self.nc.add_to_deleted_ports(fake_port2.id)
            self.nc.add_to_deleted_ports(fake_port2.id)
            self.assertEqual({fake_port1.id, fake_port2.id},
                             self.nc._deleted_ports)
            self.assertEqual([(1, fake_port1.id), (2, fake_port2.id)],
                             self.nc._deleted_ports_ts)

            self.nc.cleanup_deleted_ports()
            self.assertEqual({fake_port2.id}, self.nc._deleted_ports)
            self.assertEqual([(2, fake_port2.id)], self.nc._deleted_ports_ts)

    def test_cleanup_deleted_ports_no_old_ports(self):
        self.addCleanup(self._reset_deleted_port_max_age,
                        dhcp_agent.DELETED_PORT_MAX_AGE)
        dhcp_agent.DELETED_PORT_MAX_AGE = 10
        with mock.patch.object(timeutils, 'utcnow_ts') as mock_utcnow:
            mock_utcnow.side_effect = [1, 2, 3]
            self.nc.add_to_deleted_ports(fake_port1.id)
            self.nc.add_to_deleted_ports(fake_port2.id)
            self.assertEqual({fake_port1.id, fake_port2.id},
                             self.nc._deleted_ports)
            self.assertEqual([(1, fake_port1.id), (2, fake_port2.id)],
                             self.nc._deleted_ports_ts)

            self.nc.cleanup_deleted_ports()
            self.assertEqual({fake_port1.id, fake_port2.id},
                             self.nc._deleted_ports)
            self.assertEqual([(1, fake_port1.id), (2, fake_port2.id)],
                             self.nc._deleted_ports_ts)

    def test_cleanup_deleted_ports_no_ports(self):
        self.assertEqual(set(), self.nc._deleted_ports)
        self.assertEqual([], self.nc._deleted_ports_ts)
        self.nc.cleanup_deleted_ports()
        self.assertEqual(set(), self.nc._deleted_ports)
        self.assertEqual([], self.nc._deleted_ports_ts)

    def test_cleanup_deleted_ports_loop_call(self):
        self.addCleanup(self._reset_deleted_port_max_age,
                        dhcp_agent.DELETED_PORT_MAX_AGE)
        dhcp_agent.DELETED_PORT_MAX_AGE = 2
        nc = dhcp_agent.NetworkCache()
        nc.add_to_deleted_ports(fake_port1.id)
        utils.wait_until_true(lambda: nc._deleted_ports == set(), timeout=7)
        self.assertEqual([], self.nc._deleted_ports_ts)

        # check the second iteration is ok too
        nc.add_to_deleted_ports(fake_port2.id)
        utils.wait_until_true(lambda: nc._deleted_ports == set(), timeout=7)
        self.assertEqual([], self.nc._deleted_ports_ts)


class FakePort1(object):
    def __init__(self):
        self.id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'


class FakePort2(object):
    def __init__(self):
        self.id = 'ffffffff-ffff-ffff-ffff-ffffffffffff'


class FakeV4Subnet(object):
    def __init__(self):
        self.id = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
        self.ip_version = const.IP_VERSION_4
        self.cidr = '192.168.0.0/24'
        self.gateway_ip = '192.168.0.1'
        self.enable_dhcp = True
        self.subnetpool_id = FAKE_V4_SUBNETPOOL_ID


class FakeV6Subnet(object):
    def __init__(self):
        self.id = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
        self.ip_version = const.IP_VERSION_6
        self.cidr = '2001:db8:0:1::/64'
        self.gateway_ip = '2001:db8:0:1::1'
        self.enable_dhcp = True
        self.subnetpool_id = FAKE_V6_SUBNETPOOL_ID


class FakeV4SubnetOutsideGateway(FakeV4Subnet):
    def __init__(self):
        super(FakeV4SubnetOutsideGateway, self).__init__()
        self.gateway_ip = '192.168.1.1'


class FakeV6SubnetOutsideGateway(FakeV6Subnet):
    def __init__(self):
        super(FakeV6SubnetOutsideGateway, self).__init__()
        self.gateway_ip = '2001:db8:1:1::1'


class FakeV4SubnetNoGateway(object):
    def __init__(self):
        self.id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
        self.ip_version = const.IP_VERSION_4
        self.cidr = '192.168.1.0/24'
        self.gateway_ip = None
        self.enable_dhcp = True


class FakeV6SubnetNoGateway(object):
    def __init__(self):
        self.id = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
        self.ip_version = const.IP_VERSION_6
        self.cidr = '2001:db8:1:0::/64'
        self.gateway_ip = None
        self.enable_dhcp = True


class FakeV4Network(object):
    def __init__(self):
        self.id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        self.subnets = [FakeV4Subnet()]
        self.ports = [FakePort1()]
        self.namespace = 'qdhcp-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'


class FakeDualNetwork(object):
    def __init__(self):
        self.id = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
        self.subnets = [FakeV4Subnet(), FakeV6Subnet()]
        self.ports = [FakePort1(), FakePort2()]
        self.namespace = 'qdhcp-dddddddd-dddd-dddd-dddd-dddddddddddd'


class FakeV4NetworkOutsideGateway(FakeV4Network):
    def __init__(self):
        super(FakeV4NetworkOutsideGateway, self).__init__()
        self.subnets = [FakeV4SubnetOutsideGateway()]


class FakeDualNetworkOutsideGateway(FakeDualNetwork):
    def __init__(self):
        super(FakeDualNetworkOutsideGateway, self).__init__()
        self.subnets = [FakeV4SubnetOutsideGateway(),
                        FakeV6SubnetOutsideGateway()]


class FakeDualNetworkNoSubnet(object):
    def __init__(self):
        self.id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        self.subnets = []
        self.ports = []


class FakeDualNetworkNoGateway(object):
    def __init__(self):
        self.id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
        self.subnets = [FakeV4SubnetNoGateway(), FakeV6SubnetNoGateway()]
        self.ports = [FakePort1(), FakePort2()]


class TestDeviceManager(base.BaseTestCase):
    def setUp(self):
        super(TestDeviceManager, self).setUp()
        config.register_interface_driver_opts_helper(cfg.CONF)
        cfg.CONF.register_opts(dhcp_config.DHCP_AGENT_OPTS)
        cfg.CONF.set_override('interface_driver',
                              'neutron.agent.linux.interface.NullDriver')
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
        self.mock_driver.use_gateway_ips = False
        self.mock_iproute = mock.MagicMock()
        driver_cls.return_value = self.mock_driver
        iproute_cls.return_value = self.mock_iproute

        iptables_cls_p = mock.patch(
            'neutron.agent.linux.iptables_manager.IptablesManager')
        iptables_cls = iptables_cls_p.start()
        self.iptables_inst = mock.Mock()
        iptables_cls.return_value = self.iptables_inst
        self.mangle_inst_v4 = mock.Mock()
        self.iptables_inst.ipv4 = {'mangle': self.mangle_inst_v4}
        self.mangle_inst_v6 = mock.Mock()
        self.iptables_inst.ipv6 = {'mangle': self.mangle_inst_v6}

        self.mock_ip_wrapper_p = mock.patch("neutron.agent.linux.ip_lib."
                                            "IPWrapper")
        self.mock_ip_wrapper = self.mock_ip_wrapper_p.start()

        self.mock_ipv6_enabled_p = mock.patch.object(netutils,
                                                     'is_ipv6_enabled')
        self.mock_ipv6_enabled = self.mock_ipv6_enabled_p.start()
        self.mock_ipv6_enabled.return_value = True

    def _test_setup_helper(self, device_is_ready, ipv6_enabled=True,
                           net=None, port=None):
        net = net or fake_network
        port = port or fake_port1
        plugin = mock.Mock()
        plugin.create_dhcp_port.return_value = port or fake_port1
        self.ensure_device_is_ready.return_value = device_is_ready
        self.mock_driver.get_device_name.return_value = 'tap12345678-12'

        dh = dhcp.DeviceManager(cfg.CONF, plugin)
        dh._set_default_route = mock.Mock()
        dh.cleanup_stale_devices = mock.Mock()
        interface_name = dh.setup(net)

        self.assertEqual('tap12345678-12', interface_name)

        plugin.assert_has_calls([
            mock.call.create_dhcp_port(
                {'port': {'name': '', 'admin_state_up': True,
                          'network_id': net.id, 'project_id': net.project_id,
                          'fixed_ips':
                          [{'subnet_id': port.fixed_ips[0].subnet_id}],
                          'device_id': mock.ANY}})])

        if port == fake_ipv6_port:
            expected_ips = ['2001:db8::a8bb:ccff:fedd:ee99/64',
                            const.METADATA_CIDR]
        else:
            expected_ips = ['172.9.9.9/24', const.METADATA_CIDR]

        if ipv6_enabled:
            expected_ips.append(const.METADATA_V6_CIDR)

        expected = [mock.call.get_device_name(port)]

        if ipv6_enabled:
            expected.append(
                mock.call.configure_ipv6_ra(net.namespace, 'default', 0))

        if not device_is_ready:
            expected.append(mock.call.plug(net.id,
                                           port.id,
                                           'tap12345678-12',
                                           'aa:bb:cc:dd:ee:ff',
                                           namespace=net.namespace,
                                           mtu=None))
        expected.append(mock.call.init_l3(
                        'tap12345678-12',
                        expected_ips,
                        namespace=net.namespace))

        self.mock_driver.assert_has_calls(expected)
        dh._set_default_route.assert_called_once_with(net, 'tap12345678-12')

    def test_setup(self):
        cfg.CONF.set_override('enable_metadata_network', False)
        self._test_setup_helper(False)
        cfg.CONF.set_override('enable_metadata_network', True)
        self._test_setup_helper(False)

    def test_setup_without_ipv6_enabled(self):
        # NOTE(mjozefcz): This test checks if IPv6 RA is *not*
        # configured when host doesn't support IPv6.
        self.mock_ipv6_enabled.return_value = False
        self._test_setup_helper(False, ipv6_enabled=False)

    def test_setup_calls_fill_dhcp_udp_checksums_v4(self):
        self._test_setup_helper(False)
        rule = ('-p udp -m udp --dport %d -j CHECKSUM --checksum-fill'
                % const.DHCP_CLIENT_PORT)
        expected = [mock.call.add_rule('POSTROUTING', rule)]
        self.mangle_inst_v4.assert_has_calls(expected)

    def test_setup_calls_fill_dhcp_udp_checksums_v6(self):
        self._test_setup_helper(False)
        rule = ('-p udp -m udp --dport %d -j CHECKSUM --checksum-fill'
                % const.DHCPV6_CLIENT_PORT)
        expected = [mock.call.add_rule('POSTROUTING', rule)]
        self.mangle_inst_v6.assert_has_calls(expected)

    def test_setup_dhcp_port_doesnt_orphan_devices(self):
        with mock.patch.object(dhcp.ip_lib, 'IPDevice') as mock_IPDevice:
            plugin = mock.Mock()
            device = mock.Mock()
            mock_IPDevice.return_value = device
            device.route.get_gateway.return_value = None
            net = copy.deepcopy(fake_network)
            plugin.create_dhcp_port.side_effect = exceptions.Conflict()
            dh = dhcp.DeviceManager(cfg.CONF, plugin)
            clean = mock.patch.object(dh, 'cleanup_stale_devices').start()
            with testtools.ExpectedException(exceptions.Conflict):
                dh.setup(net)
            clean.assert_called_once_with(net, dhcp_port=None)

    def test_setup_create_dhcp_port(self):
        with mock.patch.object(dhcp.ip_lib, 'IPDevice') as mock_IPDevice:
            plugin = mock.Mock()
            device = mock.Mock()
            mock_IPDevice.return_value = device
            device.route.get_gateway.return_value = None
            net = copy.deepcopy(fake_network)
            plugin.create_dhcp_port.return_value = fake_dhcp_port
            dh = dhcp.DeviceManager(cfg.CONF, plugin)
            dh.setup(net)

            plugin.assert_has_calls([
                mock.call.create_dhcp_port(
                    {'port': {'name': '', 'admin_state_up': True,
                              'network_id': net.id,
                              'project_id': net.project_id,
                              'fixed_ips': [{'subnet_id':
                              fake_dhcp_port.fixed_ips[0].subnet_id}],
                              'device_id': mock.ANY}})])
            self.assertIn(fake_dhcp_port, net.ports)

    def test_setup_plug_exception(self):
        plugin = mock.Mock()
        plugin.create_dhcp_port.return_value = fake_dhcp_port
        self.ensure_device_is_ready.return_value = False
        self.mock_driver.get_device_name.return_value = 'tap12345678-12'
        dh = dhcp.DeviceManager(cfg.CONF, plugin)
        dh._set_default_route = mock.Mock()
        dh.cleanup_stale_devices = mock.Mock()
        dh.driver = mock.Mock()
        dh.driver.plug.side_effect = OSError()
        net = copy.deepcopy(fake_network)
        self.assertRaises(OSError, dh.setup, net)
        dh.driver.unplug.assert_called_once_with(mock.ANY,
                                                 namespace=net.namespace)
        plugin.release_dhcp_port.assert_called_once_with(
            net.id, mock.ANY)

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
                          'network_id': fake_network.id,
                          'project_id': fake_network.project_id,
                          'fixed_ips':
                          [{'subnet_id': fake_fixed_ip1.subnet_id}],
                          'device_id': mock.ANY}})])

    def test__check_dhcp_port_subnet(self):
        # this can go away once bug/1627480 is fixed
        plugin = mock.Mock()
        fake_port_copy = copy.deepcopy(fake_port1)
        fake_port_copy.fixed_ips = [fake_fixed_ip1, fake_fixed_ip_subnet2]
        plugin.get_dhcp_port.return_value = fake_port_copy
        dh = dhcp.DeviceManager(cfg.CONF, plugin)
        fake_network_copy = copy.deepcopy(fake_network)
        fake_network_copy.ports[0].device_id = dh.get_device_id(fake_network)
        fake_network_copy.subnets[1].enable_dhcp = True
        plugin.update_dhcp_port.return_value = fake_network.ports[0]
        dh.setup_dhcp_port(fake_network_copy)
        self.assertEqual(fake_port_copy, fake_network_copy.ports[0])

    def test__check_dhcp_port_subnet_port_missing_subnet(self):
        # this can go away once bug/1627480 is fixed
        plugin = mock.Mock()
        dh = dhcp.DeviceManager(cfg.CONF, plugin)
        fake_network_copy = copy.deepcopy(fake_network)
        fake_network_copy.ports[0].device_id = dh.get_device_id(fake_network)
        fake_network_copy.subnets[1].enable_dhcp = True
        plugin.update_dhcp_port.return_value = fake_network.ports[0]
        plugin.get_dhcp_port.return_value = fake_network_copy.ports[0]
        with testtools.ExpectedException(exceptions.SubnetMismatchForPort):
            dh.setup_dhcp_port(fake_network_copy)

    def test_create_dhcp_port_update_add_subnet(self):
        plugin = mock.Mock()
        dh = dhcp.DeviceManager(cfg.CONF, plugin)
        fake_network_copy = copy.deepcopy(fake_network)
        fake_network_copy.ports[0].device_id = dh.get_device_id(fake_network)
        fake_network_copy.subnets[1].enable_dhcp = True
        updated_port = copy.deepcopy(fake_network_copy.ports[0])
        updated_port.fixed_ips.append(fake_fixed_ip_subnet2)
        plugin.update_dhcp_port.return_value = updated_port
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
            dict(id=FAKE_NETWORK_UUID,
                 project_uid=FAKE_PROJECT_ID))

        with mock.patch('neutron.agent.linux.interface.NullDriver') as dvr_cls:
            mock_driver = mock.MagicMock()
            mock_driver.get_device_name.return_value = 'tap12345678-12'
            dvr_cls.return_value = mock_driver

            plugin = mock.Mock()

            dh = dhcp.DeviceManager(cfg.CONF, plugin)
            dh.destroy(fake_net, 'tap12345678-12')

            dvr_cls.assert_called_once_with(
                cfg.CONF, get_networks_callback=plugin.get_networks)
            mock_driver.assert_has_calls(
                [mock.call.unplug('tap12345678-12',
                                  namespace='qdhcp-' + fake_net.id)])
            plugin.assert_has_calls(
                [mock.call.release_dhcp_port(fake_net.id, mock.ANY)])

    def test_destroy_with_none(self):
        fake_net = dhcp.NetModel(
            dict(id=FAKE_NETWORK_UUID,
                 project_id=FAKE_PROJECT_ID))

        with mock.patch('neutron.agent.linux.interface.NullDriver') as dvr_cls:
            mock_driver = mock.MagicMock()
            mock_driver.get_device_name.return_value = 'tap12345678-12'
            dvr_cls.return_value = mock_driver

            plugin = mock.Mock()

            dh = dhcp.DeviceManager(cfg.CONF, plugin)
            dh.destroy(fake_net, None)

            dvr_cls.assert_called_once_with(
                cfg.CONF, get_networks_callback=plugin.get_networks)
            plugin.assert_has_calls(
                [mock.call.release_dhcp_port(fake_net.id, mock.ANY)])
            self.assertFalse(mock_driver.called)

    def test_get_interface_name(self):
        fake_net = dhcp.NetModel(
            dict(id=FAKE_NETWORK_UUID,
                 project_id=FAKE_PROJECT_ID))

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

            dvr_cls.assert_called_once_with(
                cfg.CONF, get_networks_callback=plugin.get_networks)
            mock_driver.assert_has_calls(
                [mock.call.get_device_name(fake_port)])

            self.assertEqual(0, len(plugin.mock_calls))

    def test_get_device_id(self):
        fake_net = dhcp.NetModel(
            dict(id=FAKE_NETWORK_UUID,
                 project_id=FAKE_PROJECT_ID))
        expected = ('dhcp1ae5f96c-c527-5079-82ea-371a01645457-12345678-1234-'
                    '5678-1234567890ab')
        # the DHCP port name only contains the hostname and not the domain name
        local_hostname = cfg.CONF.host.split('.')[0]

        with mock.patch('uuid.uuid5') as uuid5:
            uuid5.return_value = '1ae5f96c-c527-5079-82ea-371a01645457'

            dh = dhcp.DeviceManager(cfg.CONF, mock.Mock())
            self.assertEqual(expected, dh.get_device_id(fake_net))
            uuid5.assert_called_once_with(uuid.NAMESPACE_DNS, local_hostname)

    def test_update(self):
        # Try with namespaces and no metadata network
        cfg.CONF.set_override('enable_metadata_network', False)
        dh = dhcp.DeviceManager(cfg.CONF, mock.Mock())
        dh._set_default_route = mock.Mock()
        network = mock.Mock()

        dh.update(network, 'ns-12345678-12')

        dh._set_default_route.assert_called_once_with(network,
                                                      'ns-12345678-12')

        # Meta data network enabled, don't interfere with its gateway.
        cfg.CONF.set_override('enable_metadata_network', True)
        dh = dhcp.DeviceManager(cfg.CONF, mock.Mock())
        dh._set_default_route = mock.Mock()

        dh.update(FakeV4Network(), 'ns-12345678-12')

        self.assertTrue(dh._set_default_route.called)

    def test_set_default_route(self):
        dh = dhcp.DeviceManager(cfg.CONF, mock.Mock())
        with mock.patch.object(dhcp.ip_lib, 'IPDevice') as mock_IPDevice:
            device = mock.Mock()
            mock_IPDevice.return_value = device
            device.route.get_gateway.return_value = None
            # Basic one subnet with gateway.
            network = FakeV4Network()
            dh._set_default_route(network, 'tap-name')

        self.assertEqual(2, device.route.get_gateway.call_count)
        self.assertFalse(device.route.delete_gateway.called)
        device.route.add_gateway.assert_called_once_with('192.168.0.1')

    def test_set_default_route_outside_subnet(self):
        dh = dhcp.DeviceManager(cfg.CONF, mock.Mock())
        with mock.patch.object(dhcp.ip_lib, 'IPDevice') as mock_IPDevice:
            device = mock.Mock()
            mock_IPDevice.return_value = device
            device.route.get_gateway.return_value = None
            # Basic one subnet with gateway outside the subnet.
            network = FakeV4NetworkOutsideGateway()
            dh._set_default_route(network, 'tap-name')

        self.assertEqual(2, device.route.get_gateway.call_count)
        self.assertFalse(device.route.delete_gateway.called)
        device.route.add_route.assert_called_once_with('192.168.1.1',
                                                       scope='link')
        device.route.add_gateway.assert_called_once_with('192.168.1.1')

    def test_set_default_route_no_subnet(self):
        dh = dhcp.DeviceManager(cfg.CONF, mock.Mock())
        with mock.patch.object(dhcp.ip_lib, 'IPDevice') as mock_IPDevice:
            device = mock.Mock()
            mock_IPDevice.return_value = device
            device.route.get_gateway.return_value = None
            network = FakeDualNetworkNoSubnet()
            network.namespace = 'qdhcp-1234'
            dh._set_default_route(network, 'tap-name')

        self.assertEqual(2, device.route.get_gateway.call_count)
        self.assertFalse(device.route.delete_gateway.called)
        self.assertFalse(device.route.add_gateway.called)

    def test_set_default_route_no_subnet_delete_gateway(self):
        dh = dhcp.DeviceManager(cfg.CONF, mock.Mock())
        v4_gateway = '192.168.0.1'
        v6_gateway = '2001:db8:0:1::1'
        expected = [mock.call(v4_gateway),
                    mock.call(v6_gateway)]
        with mock.patch.object(dhcp.ip_lib, 'IPDevice') as mock_IPDevice:
            device = mock.Mock()
            mock_IPDevice.return_value = device
            device.route.get_gateway.side_effect = [
                dict(gateway=v4_gateway), dict(gateway=v6_gateway)]
            network = FakeDualNetworkNoSubnet()
            network.namespace = 'qdhcp-1234'
            dh._set_default_route(network, 'tap-name')

        self.assertEqual(2, device.route.get_gateway.call_count)
        self.assertEqual(2, device.route.delete_gateway.call_count)
        device.route.delete_gateway.assert_has_calls(expected)
        self.assertFalse(device.route.add_gateway.called)

    def test_set_default_route_no_gateway(self):
        dh = dhcp.DeviceManager(cfg.CONF, mock.Mock())
        v4_gateway = '192.168.0.1'
        v6_gateway = '2001:db8:0:1::1'
        expected = [mock.call(v4_gateway),
                    mock.call(v6_gateway)]
        with mock.patch.object(dhcp.ip_lib, 'IPDevice') as mock_IPDevice:
            device = mock.Mock()
            mock_IPDevice.return_value = device
            device.route.get_gateway.side_effect = [
                dict(gateway=v4_gateway), dict(gateway=v6_gateway)]
            network = FakeDualNetworkNoGateway()
            network.namespace = 'qdhcp-1234'
            dh._set_default_route(network, 'tap-name')

        self.assertEqual(2, device.route.get_gateway.call_count)
        self.assertEqual(2, device.route.delete_gateway.call_count)
        device.route.delete_gateway.assert_has_calls(expected)
        self.assertFalse(device.route.add_gateway.called)

    def test_set_default_route_do_nothing(self):
        dh = dhcp.DeviceManager(cfg.CONF, mock.Mock())
        v4_gateway = '192.168.0.1'
        v6_gateway = '2001:db8:0:1::1'
        with mock.patch.object(dhcp.ip_lib, 'IPDevice') as mock_IPDevice:
            device = mock.Mock()
            mock_IPDevice.return_value = device
            device.route.get_gateway.side_effect = [
                dict(gateway=v4_gateway), dict(gateway=v6_gateway)]
            network = FakeDualNetwork()
            dh._set_default_route(network, 'tap-name')

        self.assertEqual(2, device.route.get_gateway.call_count)
        self.assertFalse(device.route.delete_gateway.called)
        self.assertFalse(device.route.add_gateway.called)

    def test_set_default_route_change_gateway(self):
        dh = dhcp.DeviceManager(cfg.CONF, mock.Mock())
        v4_gateway = '192.168.0.1'
        old_v4_gateway = '192.168.0.2'
        v6_gateway = '2001:db8:0:1::1'
        old_v6_gateway = '2001:db8:0:1::2'
        expected = [mock.call(v4_gateway),
                    mock.call(v6_gateway)]
        with mock.patch.object(dhcp.ip_lib, 'IPDevice') as mock_IPDevice:
            device = mock.Mock()
            mock_IPDevice.return_value = device
            device.route.get_gateway.side_effect = [
                dict(gateway=old_v4_gateway), dict(gateway=old_v6_gateway)]
            network = FakeDualNetwork()
            dh._set_default_route(network, 'tap-name')

        self.assertEqual(2, device.route.get_gateway.call_count)
        self.assertFalse(device.route.delete_gateway.called)
        device.route.add_gateway.assert_has_calls(expected)

    def test_set_default_route_change_gateway_outside_subnet(self):
        dh = dhcp.DeviceManager(cfg.CONF, mock.Mock())
        v4_gateway = '192.168.1.1'
        old_v4_gateway = '192.168.2.1'
        v6_gateway = '2001:db8:1:1::1'
        old_v6_gateway = '2001:db8:2:0::1'
        add_route_expected = [mock.call(v4_gateway, scope='link'),
                              mock.call(v6_gateway, scope='link')]
        add_gw_expected = [mock.call(v4_gateway),
                           mock.call(v6_gateway)]
        with mock.patch.object(dhcp.ip_lib, 'IPDevice') as mock_IPDevice:
            device = mock.Mock()
            mock_IPDevice.return_value = device
            device.route.list_onlink_routes.side_effect = [
                [{'cidr': old_v4_gateway}], []]
            device.route.get_gateway.side_effect = [
                dict(gateway=old_v4_gateway), dict(gateway=old_v6_gateway)]
            network = FakeDualNetworkOutsideGateway()
            dh._set_default_route(network, 'tap-name')

        self.assertEqual(2, device.route.get_gateway.call_count)
        self.assertEqual(2, device.route.list_onlink_routes.call_count)
        self.assertFalse(device.route.delete_gateway.called)
        device.route.delete_route.assert_called_once_with(old_v4_gateway,
                                                       scope='link')
        device.route.add_route.assert_has_calls(add_route_expected)
        device.route.add_gateway.assert_has_calls(add_gw_expected)

    def test_set_default_route_two_subnets(self):
        # Try two subnets. Should set gateway from the first.
        dh = dhcp.DeviceManager(cfg.CONF, mock.Mock())
        v4_gateway = '192.168.1.1'
        v6_gateway = '2001:db8:1:1::1'
        expected = [mock.call(v4_gateway),
                    mock.call(v6_gateway)]
        with mock.patch.object(dhcp.ip_lib, 'IPDevice') as mock_IPDevice:
            device = mock.Mock()
            mock_IPDevice.return_value = device
            device.route.get_gateway.return_value = None
            network = FakeDualNetwork()
            subnet2 = FakeV4Subnet()
            subnet2.gateway_ip = v4_gateway
            subnet3 = FakeV6Subnet()
            subnet3.gateway_ip = v6_gateway
            network.subnets = [subnet2, FakeV4Subnet(),
                               subnet3, FakeV6Subnet()]
            dh._set_default_route(network, 'tap-name')

        self.assertEqual(2, device.route.get_gateway.call_count)
        self.assertFalse(device.route.delete_gateway.called)
        device.route.add_gateway.assert_has_calls(expected)


class TestDHCPResourceUpdate(base.BaseTestCase):

    date1 = datetime.datetime(year=2021, month=2, day=1, hour=9, minute=1,
                              second=2)
    date2 = datetime.datetime(year=2021, month=2, day=1, hour=9, minute=1,
                              second=1)  # older than date1

    def test__lt__no_port_event(self):
        # Lower numerical priority always gets precedence. DHCPResourceUpdate
        # (and ResourceUpdate) objects with more precedence will return as
        # "lower" in a "__lt__" method comparison.
        update1 = dhcp_agent.DHCPResourceUpdate('id1', 5, obj_type='network')
        update2 = dhcp_agent.DHCPResourceUpdate('id2', 6, obj_type='network')
        self.assertLess(update1, update2)

    def test__lt__no_port_event_timestamp(self):
        update1 = dhcp_agent.DHCPResourceUpdate(
            'id1', 5, timestamp=self.date1, obj_type='network')
        update2 = dhcp_agent.DHCPResourceUpdate(
            'id2', 6, timestamp=self.date2, obj_type='network')
        self.assertLess(update1, update2)

    def test__lt__port_fixed_ips_not_matching(self):
        resource1 = {'fixed_ips': [
            {'subnet_id': 'subnet1', 'ip_address': '10.0.0.1'}]}
        resource2 = {'fixed_ips': [
            {'subnet_id': 'subnet1', 'ip_address': '10.0.0.2'},
            {'subnet_id': 'subnet2', 'ip_address': '10.0.1.1'}]}
        update1 = dhcp_agent.DHCPResourceUpdate(
            'id1', 5, timestamp=self.date1, resource=resource1,
            obj_type='port')
        update2 = dhcp_agent.DHCPResourceUpdate(
            'id2', 6, timestamp=self.date2, resource=resource2,
            obj_type='port')
        self.assertLess(update1, update2)

    def test__lt__port_fixed_ips_matching(self):
        resource1 = {'fixed_ips': [
            {'subnet_id': 'subnet1', 'ip_address': '10.0.0.1'}]}
        resource2 = {'fixed_ips': [
            {'subnet_id': 'subnet1', 'ip_address': '10.0.0.1'},
            {'subnet_id': 'subnet2', 'ip_address': '10.0.0.2'}]}
        update1 = dhcp_agent.DHCPResourceUpdate(
            'id1', 5, timestamp=self.date1, resource=resource1,
            obj_type='port')
        update2 = dhcp_agent.DHCPResourceUpdate(
            'id2', 6, timestamp=self.date2, resource=resource2,
            obj_type='port')
        # In this case, both "port" events have matching IPs. "__lt__" method
        # uses the timestamp: date2 < date1
        self.assertLess(update2, update1)
