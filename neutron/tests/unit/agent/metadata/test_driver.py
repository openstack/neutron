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

import mock
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.agent.l3 import agent as l3_agent
from neutron.agent.l3 import router_info
from neutron.agent.linux import iptables_manager
from neutron.agent.metadata import driver as metadata_driver
from neutron.common import constants
from neutron.conf.agent import common as agent_config
from neutron.conf.agent.l3 import config as l3_config
from neutron.conf.agent.l3 import ha as ha_conf
from neutron.conf.agent.metadata import config as meta_conf
from neutron.tests import base
from neutron.tests import tools
from neutron.tests.unit.agent.linux import test_utils

_uuid = uuidutils.generate_uuid


class TestMetadataDriverRules(base.BaseTestCase):

    def test_metadata_nat_rules(self):
        rules = ('PREROUTING', '-d 169.254.169.254/32 -i qr-+ '
                 '-p tcp -m tcp --dport 80 -j REDIRECT --to-ports 9697')
        self.assertEqual(
            [rules],
            metadata_driver.MetadataDriver.metadata_nat_rules(9697))

    def test_metadata_filter_rules(self):
        rules = [('INPUT', '-m mark --mark 0x1/%s -j ACCEPT' %
                  constants.ROUTER_MARK_MASK),
                 ('INPUT', '-p tcp -m tcp --dport 9697 -j DROP')]
        self.assertEqual(
            rules,
            metadata_driver.MetadataDriver.metadata_filter_rules(9697, '0x1'))

    def test_metadata_checksum_rules(self):
        rules = ('POSTROUTING', '-o qr-+ -p tcp -m tcp --sport 9697 '
                 '-j CHECKSUM --checksum-fill')
        self.assertEqual(
            [rules],
            metadata_driver.MetadataDriver.metadata_checksum_rules(9697))


class TestMetadataDriverProcess(base.BaseTestCase):

    EUNAME = 'neutron'
    EGNAME = 'neutron'
    METADATA_DEFAULT_IP = '169.254.169.254'
    METADATA_PORT = 8080
    METADATA_SOCKET = '/socket/path'
    PIDFILE = 'pidfile'

    def setUp(self):
        super(TestMetadataDriverProcess, self).setUp()
        mock.patch('eventlet.spawn').start()
        agent_config.register_interface_driver_opts_helper(cfg.CONF)
        cfg.CONF.set_override('interface_driver',
                              'neutron.agent.linux.interface.NullDriver')

        mock.patch('neutron.agent.l3.agent.L3PluginApi').start()
        mock.patch('neutron.agent.l3.ha.AgentMixin'
                   '._init_ha_conf_path').start()

        l3_config.register_l3_agent_config_opts(l3_config.OPTS, cfg.CONF)
        ha_conf.register_l3_agent_ha_opts()
        meta_conf.register_meta_conf_opts(meta_conf.SHARED_OPTS, cfg.CONF)

    def test_after_router_updated_called_on_agent_process_update(self):
        with mock.patch.object(metadata_driver, 'after_router_updated') as f,\
                mock.patch.object(router_info.RouterInfo, 'process'):
            agent = l3_agent.L3NATAgent('localhost')
            router_id = _uuid()
            router = {'id': router_id}
            ri = router_info.RouterInfo(mock.Mock(), router_id, router,
                                        agent.conf, mock.ANY)
            agent.router_info[router_id] = ri
            agent._process_updated_router(router)
            f.assert_called_once_with(
                'router', 'after_update', agent, router=ri)

    def test_after_router_updated_should_not_call_add_metadata_rules(self):
        with mock.patch.object(iptables_manager.IptablesTable,
                               'add_rule') as f,\
                mock.patch.object(iptables_manager.IptablesManager,
                                  'apply'),\
                mock.patch.object(metadata_driver.MetadataDriver,
                                  'spawn_monitored_metadata_proxy'),\
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

    def test_spawn_metadata_proxy(self):
        router_id = _uuid()
        router_ns = 'qrouter-%s' % router_id
        ip_class_path = 'neutron.agent.linux.ip_lib.IPWrapper'

        cfg.CONF.set_override('metadata_proxy_user', self.EUNAME)
        cfg.CONF.set_override('metadata_proxy_group', self.EGNAME)
        cfg.CONF.set_override('metadata_proxy_socket', self.METADATA_SOCKET)
        cfg.CONF.set_override('debug', True)

        agent = l3_agent.L3NATAgent('localhost')
        with mock.patch(ip_class_path) as ip_mock,\
                mock.patch(
                    'neutron.agent.linux.external_process.'
                    'ProcessManager.get_pid_file_name',
                    return_value=self.PIDFILE),\
                mock.patch('pwd.getpwnam',
                           return_value=test_utils.FakeUser(self.EUNAME)),\
                mock.patch('grp.getgrnam',
                           return_value=test_utils.FakeGroup(self.EGNAME)),\
                mock.patch('os.makedirs'):
            cfg_file = os.path.join(
                metadata_driver.HaproxyConfigurator.get_config_path(
                    agent.conf.state_path),
                "%s.conf" % router_id)
            mock_open = self.useFixture(
                tools.OpenFixture(cfg_file)).mock_open
            agent.metadata_driver.spawn_monitored_metadata_proxy(
                agent.process_monitor,
                router_ns,
                self.METADATA_PORT,
                agent.conf,
                bind_address=self.METADATA_DEFAULT_IP,
                router_id=router_id)

            netns_execute_args = [
                'haproxy',
                '-f', cfg_file]

            log_tag = ("haproxy-" + metadata_driver.METADATA_SERVICE_NAME +
                       "-" + router_id)
            cfg_contents = metadata_driver._HAPROXY_CONFIG_TEMPLATE % {
                'user': self.EUNAME,
                'group': self.EGNAME,
                'host': self.METADATA_DEFAULT_IP,
                'port': self.METADATA_PORT,
                'unix_socket_path': self.METADATA_SOCKET,
                'res_type': 'Router',
                'res_id': router_id,
                'pidfile': self.PIDFILE,
                'log_level': 'debug',
                'log_tag': log_tag}

            mock_open.assert_has_calls([
                mock.call(cfg_file, 'w'),
                mock.call().write(cfg_contents)],
                                       any_order=True)

            ip_mock.assert_has_calls([
                mock.call(namespace=router_ns),
                mock.call().netns.execute(netns_execute_args, addl_env=None,
                                          run_as_root=True)
            ])

    def test_create_config_file_wrong_user(self):
        with mock.patch('pwd.getpwnam', side_effect=KeyError):
            config = metadata_driver.HaproxyConfigurator(_uuid(),
                                                         mock.ANY, mock.ANY,
                                                         mock.ANY, mock.ANY,
                                                         self.EUNAME,
                                                         self.EGNAME,
                                                         mock.ANY, mock.ANY)
            self.assertRaises(metadata_driver.InvalidUserOrGroupException,
                              config.create_config_file)

    def test_create_config_file_wrong_group(self):
        with mock.patch('grp.getgrnam', side_effect=KeyError),\
                mock.patch('pwd.getpwnam',
                           return_value=test_utils.FakeUser(self.EUNAME)):
            config = metadata_driver.HaproxyConfigurator(_uuid(),
                                                         mock.ANY, mock.ANY,
                                                         mock.ANY, mock.ANY,
                                                         self.EUNAME,
                                                         self.EGNAME,
                                                         mock.ANY, mock.ANY)
            self.assertRaises(metadata_driver.InvalidUserOrGroupException,
                              config.create_config_file)
