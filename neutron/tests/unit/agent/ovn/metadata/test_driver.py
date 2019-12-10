# Copyright 2017 OpenStack Foundation.
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
from neutron_lib import fixture as lib_fixtures
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.agent.ovn.metadata import agent as metadata_agent
from neutron.agent.ovn.metadata import driver as metadata_driver
from neutron.conf.agent.metadata import config as meta_conf
from neutron.conf.agent.ovn.metadata import config as ovn_meta_conf
from neutron.tests import base
from neutron.tests.unit.agent.linux import test_utils

_uuid = uuidutils.generate_uuid


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

        ovn_meta_conf.register_meta_conf_opts(meta_conf.SHARED_OPTS, cfg.CONF)

    def test_spawn_metadata_proxy(self):
        datapath_id = _uuid()
        metadata_ns = metadata_agent.NS_PREFIX + datapath_id
        ip_class_path = 'neutron.agent.linux.ip_lib.IPWrapper'

        cfg.CONF.set_override('metadata_proxy_user', self.EUNAME)
        cfg.CONF.set_override('metadata_proxy_group', self.EGNAME)
        cfg.CONF.set_override('metadata_proxy_socket', self.METADATA_SOCKET)
        cfg.CONF.set_override('debug', True)

        agent = metadata_agent.MetadataAgent(cfg.CONF)
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
                    cfg.CONF.state_path),
                "%s.conf" % datapath_id)
            mock_open = self.useFixture(
                lib_fixtures.OpenFixture(cfg_file)).mock_open
            metadata_driver.MetadataDriver.spawn_monitored_metadata_proxy(
                agent._process_monitor,
                metadata_ns,
                self.METADATA_PORT,
                cfg.CONF,
                bind_address=self.METADATA_DEFAULT_IP,
                network_id=datapath_id)

            netns_execute_args = [
                'haproxy',
                '-f', cfg_file]

            cfg_contents = metadata_driver._HAPROXY_CONFIG_TEMPLATE % {
                'user': self.EUNAME,
                'group': self.EGNAME,
                'host': self.METADATA_DEFAULT_IP,
                'port': self.METADATA_PORT,
                'unix_socket_path': self.METADATA_SOCKET,
                'res_type': 'Network',
                'res_id': datapath_id,
                'pidfile': self.PIDFILE,
                'log_level': 'debug'}

            mock_open.assert_has_calls([
                mock.call(cfg_file, 'w'),
                mock.call().write(cfg_contents)],
                any_order=True)

            ip_mock.assert_has_calls([
                mock.call(namespace=metadata_ns),
                mock.call().netns.execute(netns_execute_args, addl_env=None,
                                          run_as_root=True)
            ])

    def test_create_config_file_wrong_user(self):
        with mock.patch('pwd.getpwnam', side_effect=KeyError):
            config = metadata_driver.HaproxyConfigurator(mock.ANY, mock.ANY,
                                                         mock.ANY, mock.ANY,
                                                         mock.ANY, self.EUNAME,
                                                         self.EGNAME, mock.ANY,
                                                         mock.ANY)
            self.assertRaises(metadata_driver.InvalidUserOrGroupException,
                              config.create_config_file)

    def test_create_config_file_wrong_group(self):
        with mock.patch('grp.getgrnam', side_effect=KeyError),\
                mock.patch('pwd.getpwnam',
                           return_value=test_utils.FakeUser(self.EUNAME)):
            config = metadata_driver.HaproxyConfigurator(mock.ANY, mock.ANY,
                                                         mock.ANY, mock.ANY,
                                                         mock.ANY, self.EUNAME,
                                                         self.EGNAME, mock.ANY,
                                                         mock.ANY)
            self.assertRaises(metadata_driver.InvalidUserOrGroupException,
                              config.create_config_file)
