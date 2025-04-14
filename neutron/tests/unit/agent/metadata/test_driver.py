# Copyright 2014 OpenStack Foundation.
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

import os
import signal
from unittest import mock

from neutron_lib import constants
from neutron_lib import exceptions as lib_exceptions
from neutron_lib import fixture as lib_fixtures
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.agent.l3 import agent as l3_agent
from neutron.agent.l3 import router_info
from neutron.agent.linux import external_process as ep
from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_manager
from neutron.agent.linux import utils as linux_utils
from neutron.agent.metadata import driver as metadata_driver
from neutron.agent.metadata import driver_base
from neutron.common import metadata as comm_meta
from neutron.conf.agent import common as agent_config
from neutron.conf.agent.l3 import config as l3_config
from neutron.conf.agent.l3 import ha as ha_conf
from neutron.conf.agent.metadata import config as meta_conf
from neutron.tests import base
from neutron.tests.unit.agent.linux import test_utils

_uuid = uuidutils.generate_uuid


class FakeL3NATAgent(object):

    def __init__(self):
        self.conf = cfg.CONF


class TestMetadataDriverRules(base.BaseTestCase):

    def test_metadata_nat_rules(self):
        rules = ('PREROUTING', '-d 169.254.169.254/32 -i qr-+ '
                 '-p tcp -m tcp --dport 80 -j REDIRECT --to-ports 9697')
        self.assertEqual(
            [rules],
            metadata_driver.metadata_nat_rules(9697))

    def test_metadata_nat_rules_ipv6(self):
        rules = ('PREROUTING', '-d fe80::a9fe:a9fe/128 -i qr-+ '
                 '-p tcp -m tcp --dport 80 -j REDIRECT --to-ports 9697')
        self.assertEqual(
            [rules],
            metadata_driver.metadata_nat_rules(
                9697, metadata_address='fe80::a9fe:a9fe/128'))

    def test_metadata_filter_rules(self):
        rules = [('INPUT', '-m mark --mark 0x1/%s -j ACCEPT' %
                  constants.ROUTER_MARK_MASK),
                 ('INPUT', '-p tcp -m tcp --dport 9697 -j DROP')]
        self.assertEqual(
            rules,
            metadata_driver.metadata_filter_rules(9697, '0x1'))


class TestMetadataDriverProcess(base.BaseTestCase):

    EUNAME = 'neutron'
    EGNAME = 'neutron'
    METADATA_DEFAULT_IP = '169.254.169.254'
    METADATA_DEFAULT_IPV6 = 'fe80::a9fe:a9fe'
    METADATA_PORT = 8080
    METADATA_SOCKET = '/socket/path'
    PIDFILE = 'pidfile'
    RATE_LIMIT_CONFIG = {
        'base_window_duration': 10,
        'base_query_rate_limit': 5,
        'burst_window_duration': 1,
        'burst_query_rate_limit': 10,
    }

    def setUp(self):
        super(TestMetadataDriverProcess, self).setUp()
        mock.patch('eventlet.spawn').start()
        agent_config.register_interface_driver_opts_helper(cfg.CONF)
        cfg.CONF.set_override('interface_driver',
                              'neutron.agent.linux.interface.NullDriver')

        mock.patch('neutron.agent.l3.agent.L3PluginApi').start()
        mock.patch('neutron.agent.l3.ha.AgentMixin'
                   '._init_ha_conf_path').start()
        self.delete_if_exists = mock.patch.object(linux_utils,
                                                  'delete_if_exists').start()
        self.mock_get_process = mock.patch.object(
            metadata_driver.MetadataDriver,
            '_get_metadata_proxy_process_manager')

        l3_config.register_l3_agent_config_opts(l3_config.OPTS, cfg.CONF)
        ha_conf.register_l3_agent_ha_opts()
        meta_conf.register_meta_conf_opts(meta_conf.SHARED_OPTS, cfg.CONF)
        meta_conf.register_meta_conf_opts(
            meta_conf.METADATA_RATE_LIMITING_OPTS, cfg.CONF,
            group=meta_conf.RATE_LIMITING_GROUP)
        self.mock_conf_obsolete = mock.patch.object(
            driver_base.HaproxyConfiguratorBase,
            'is_config_file_obsolete').start()

    def test_after_router_updated_called_on_agent_process_update(self):
        with mock.patch.object(metadata_driver, 'after_router_updated') as f,\
                mock.patch('neutron.agent.l3.namespace_manager.'
                           'NamespaceManager.list_all', return_value={}),\
                mock.patch.object(router_info.RouterInfo, 'process'):
            agent = l3_agent.L3NATAgent('localhost')
            router_id = _uuid()
            router = {'id': router_id}
            ri = router_info.RouterInfo(mock.Mock(), router_id, router,
                                        agent.conf, mock.ANY)
            agent.router_info[router_id] = ri
            agent._process_updated_router(router)
            f.assert_called_once_with(
                'router', 'after_update', agent,
                payload=mock.ANY)

            payload = f.call_args_list[0][1]['payload']
            self.assertEqual(ri, payload.latest_state)
            self.assertEqual(router_id, payload.resource_id)

    def test_after_router_updated_should_not_call_add_metadata_rules(self):
        with mock.patch.object(iptables_manager.IptablesTable,
                               'add_rule') as f,\
                mock.patch.object(iptables_manager.IptablesManager,
                                  'apply'),\
                mock.patch.object(metadata_driver.MetadataDriver,
                                  'spawn_monitored_metadata_proxy'),\
                mock.patch('neutron.agent.l3.namespace_manager.'
                           'NamespaceManager.list_all', return_value={}),\
                mock.patch.object(router_info.RouterInfo, 'process'):
            agent = l3_agent.L3NATAgent('localhost')
            router_id = _uuid()
            router = {'id': router_id}
            ri = router_info.RouterInfo(mock.Mock(), router_id, router,
                                        agent.conf, mock.ANY)
            agent.router_info[router_id] = ri
            f.reset_mock()
            agent._process_updated_router(router)
            f.assert_not_called()

    def _test_spawn_metadata_proxy(self, dad_failed=False, rate_limited=False,
                                   is_config_file_obsolete=False):
        router_id = _uuid()
        router_ns = 'qrouter-%s' % router_id
        service_name = 'haproxy'
        ip_class_path = 'neutron.agent.linux.ip_lib.IPWrapper'

        cfg.CONF.set_override('metadata_proxy_user', self.EUNAME)
        cfg.CONF.set_override('metadata_proxy_group', self.EGNAME)
        cfg.CONF.set_override('metadata_proxy_socket', self.METADATA_SOCKET)
        cfg.CONF.set_override('debug', True)
        self.mock_conf_obsolete.return_value = is_config_file_obsolete
        if is_config_file_obsolete:
            self.mock_destroy_haproxy = mock.patch.object(
                driver_base.MetadataDriverBase,
                'destroy_monitored_metadata_proxy').start()

        with mock.patch(ip_class_path) as ip_mock,\
                mock.patch(
                    'neutron.agent.linux.external_process.'
                    'ProcessManager.get_pid_file_name',
                    return_value=self.PIDFILE),\
                mock.patch('pwd.getpwnam',
                           return_value=test_utils.FakeUser(self.EUNAME)),\
                mock.patch('grp.getgrnam',
                           return_value=test_utils.FakeGroup(self.EGNAME)),\
                mock.patch('os.makedirs'),\
                mock.patch('neutron.agent.l3.namespace_manager.'
                           'NamespaceManager.list_all', return_value={}),\
                mock.patch(
                    'neutron.agent.linux.ip_lib.'
                    'IpAddrCommand.wait_until_address_ready') as mock_wait,\
                mock.patch(
                    'neutron.agent.linux.ip_lib.'
                    'delete_ip_address') as mock_del,\
                mock.patch(
                    'neutron.agent.linux.external_process.'
                    'ProcessManager.active',
                    new_callable=mock.PropertyMock,
                    side_effect=[False, True]):
            agent = l3_agent.L3NATAgent('localhost')
            agent.process_monitor = mock.Mock()
            cfg_file = os.path.join(
                metadata_driver.HaproxyConfigurator.get_config_path(
                    agent.conf.state_path),
                "%s.conf" % router_id)
            mock_open = self.useFixture(
                lib_fixtures.OpenFixture(cfg_file)).mock_open
            bind_v6_line = 'bind %s:%s interface %s' % (
                self.METADATA_DEFAULT_IPV6, self.METADATA_PORT, 'fake-if')
            if dad_failed:
                mock_wait.side_effect = ip_lib.DADFailed(
                    address=self.METADATA_DEFAULT_IPV6, reason='DAD failed')
                bind_v6_line = ''
            else:
                mock_wait.return_value = True
            agent.metadata_driver.spawn_monitored_metadata_proxy(
                agent.process_monitor,
                router_ns,
                self.METADATA_PORT,
                agent.conf,
                bind_address=self.METADATA_DEFAULT_IP,
                router_id=router_id,
                bind_address_v6=self.METADATA_DEFAULT_IPV6,
                bind_interface='fake-if')

            netns_execute_args = [
                service_name,
                '-f', cfg_file]

            log_tag = ("haproxy-" + driver_base.METADATA_SERVICE_NAME +
                       "-" + router_id)

            expected_params = {
                'user': self.EUNAME,
                'group': self.EGNAME,
                'host': self.METADATA_DEFAULT_IP,
                'port': self.METADATA_PORT,
                'unix_socket_path': self.METADATA_SOCKET,
                'res_type': 'Router',
                'res_id': router_id,
                'res_type_del': 'Network',
                'pidfile': self.PIDFILE,
                'log_level': 'debug',
                'log_tag': log_tag,
                'bind_v6_line': bind_v6_line}

            if dad_failed:
                mock_del.assert_called_once_with(self.METADATA_DEFAULT_IPV6,
                                                 'fake-if',
                                                 namespace=router_ns)
            else:
                mock_del.assert_not_called()

            if rate_limited:
                expected_params.update(self.RATE_LIMIT_CONFIG,
                                       stick_table_expire=10,
                                       ip_version='ip')
                expected_config_template = (
                    comm_meta.METADATA_HAPROXY_GLOBAL +
                    comm_meta.RATE_LIMITED_CONFIG_TEMPLATE +
                    metadata_driver._HEADER_CONFIG_TEMPLATE)
            else:
                expected_config_template = (
                    comm_meta.METADATA_HAPROXY_GLOBAL +
                    driver_base._UNLIMITED_CONFIG_TEMPLATE +
                    metadata_driver._HEADER_CONFIG_TEMPLATE)

            mock_open.assert_has_calls([
                mock.call(cfg_file, 'w'),
                mock.call().write(expected_config_template %
                                  expected_params)], any_order=True)

            env = {ep.PROCESS_TAG: service_name + '-' + router_id}
            ip_mock.assert_has_calls([
                mock.call(namespace=router_ns),
                mock.call().netns.execute(netns_execute_args, addl_env=env,
                                          run_as_root=True)
            ])

            agent.process_monitor.register.assert_called_once_with(
                router_id, driver_base.METADATA_SERVICE_NAME,
                mock.ANY)

            self.delete_if_exists.assert_called_once_with(
                mock.ANY, run_as_root=True)

            if is_config_file_obsolete:
                self.mock_destroy_haproxy.assert_called_once_with(
                    agent.process_monitor, router_id, agent.conf, router_ns)

    def test_spawn_metadata_proxy(self):
        self._test_spawn_metadata_proxy()

    def test_spawn_rate_limited_metadata_proxy(self):
        cfg.CONF.set_override('rate_limit_enabled', True,
                              group=meta_conf.RATE_LIMITING_GROUP)
        for k, v in self.RATE_LIMIT_CONFIG.items():
            cfg.CONF.set_override(k, v, group=meta_conf.RATE_LIMITING_GROUP)

        return self._test_spawn_metadata_proxy(rate_limited=True)

    def test_metadata_proxy_conf_parse_ip_versions(self):
        self.assertEqual(4, comm_meta.parse_ip_versions([4]))
        self.assertEqual(6, comm_meta.parse_ip_versions([6]))
        self.assertIsNone(comm_meta.parse_ip_versions([4, 6]))
        self.assertIsNone(comm_meta.parse_ip_versions([5, 6]))

    def test_spawn_metadata_proxy_dad_failed(self):
        self._test_spawn_metadata_proxy(dad_failed=True)

    def test_spawn_metadata_proxy_no_matching_configurations(self):
        self._test_spawn_metadata_proxy(is_config_file_obsolete=True)

    @mock.patch.object(driver_base.LOG, 'error')
    def test_spawn_metadata_proxy_handles_process_exception(self, error_log):
        process_instance = mock.Mock(active=False)
        process_instance.enable.side_effect = (
            lib_exceptions.ProcessExecutionError('Something happened', -1))
        with mock.patch.object(metadata_driver.MetadataDriver,
                               '_get_metadata_proxy_process_manager',
                               return_value=process_instance):
            process_monitor = mock.Mock()
            network_id = 123456
            metadata_driver.MetadataDriver.spawn_monitored_metadata_proxy(
                process_monitor,
                'dummy_namespace',
                self.METADATA_PORT,
                cfg.CONF,
                network_id=network_id)
        error_log.assert_called_once()
        process_monitor.register.assert_not_called()
        self.assertNotIn(network_id, metadata_driver.MetadataDriver.monitors)

    def test_create_config_file_wrong_user(self):
        with mock.patch('pwd.getpwnam', side_effect=KeyError):
            self.assertRaises(comm_meta.InvalidUserOrGroupException,
                              metadata_driver.HaproxyConfigurator, _uuid(),
                              mock.ANY, mock.ANY, mock.ANY, mock.ANY,
                              self.EUNAME, self.EGNAME, mock.ANY, mock.ANY,
                              mock.ANY)

    def test_create_config_file_wrong_group(self):
        with mock.patch('grp.getgrnam', side_effect=KeyError),\
                mock.patch('pwd.getpwnam',
                           return_value=test_utils.FakeUser(self.EUNAME)):
            self.assertRaises(comm_meta.InvalidUserOrGroupException,
                              metadata_driver.HaproxyConfigurator, _uuid(),
                              mock.ANY, mock.ANY, mock.ANY, mock.ANY,
                              self.EUNAME, self.EGNAME, mock.ANY, mock.ANY,
                              mock.ANY)

    def test_destroy_monitored_metadata_proxy(self):
        mproxy_process = mock.Mock(active=False)
        mock_get_process = self.mock_get_process.start()
        mock_get_process.return_value = mproxy_process
        driver = metadata_driver.MetadataDriver(FakeL3NATAgent())
        driver.destroy_monitored_metadata_proxy(mock.Mock(), 'uuid', 'conf',
                                                'ns_name')
        mproxy_process.disable.assert_called_once_with(
            sig=str(int(signal.SIGTERM)))
        self.delete_if_exists.assert_called_once_with(
            mock.ANY, run_as_root=True)

    def test_destroy_monitored_metadata_proxy_force(self):
        mproxy_process = mock.Mock(active=True)
        mock_get_process = self.mock_get_process.start()
        mock_get_process.return_value = mproxy_process
        driver = metadata_driver.MetadataDriver(FakeL3NATAgent())
        with mock.patch.object(driver_base, 'SIGTERM_TIMEOUT', 0):
            driver.destroy_monitored_metadata_proxy(mock.Mock(), 'uuid',
                                                    'conf', 'ns_name')
        mproxy_process.disable.assert_has_calls([
            mock.call(sig=str(int(signal.SIGTERM))),
            mock.call(sig=str(int(signal.SIGKILL)))])
        self.delete_if_exists.assert_called_once_with(
            mock.ANY, run_as_root=True)
