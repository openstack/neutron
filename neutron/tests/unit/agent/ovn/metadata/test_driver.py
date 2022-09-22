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
from unittest import mock

from neutron_lib import fixture as lib_fixtures
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.agent.linux import external_process as ep
from neutron.agent.ovn.metadata import agent as metadata_agent
from neutron.agent.ovn.metadata import driver as metadata_driver
from neutron.common import metadata as comm_meta
from neutron.conf.agent.metadata import config as meta_conf
from neutron.conf.agent.ovn.metadata import config as ovn_meta_conf
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
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
    RATE_LIMIT_CONFIG = {
        'base_window_duration': 10,
        'base_query_rate_limit': 5,
        'burst_window_duration': 1,
        'burst_query_rate_limit': 10,
    }

    def setUp(self):
        super(TestMetadataDriverProcess, self).setUp()
        mock.patch('eventlet.spawn').start()

        ovn_meta_conf.register_meta_conf_opts(meta_conf.SHARED_OPTS, cfg.CONF)
        ovn_meta_conf.register_meta_conf_opts(
            meta_conf.METADATA_RATE_LIMITING_OPTS, cfg.CONF,
            group=meta_conf.RATE_LIMITING_GROUP)
        ovn_conf.register_opts()

    def test_spawn_metadata_proxy(self):
        return self._test_spawn_metadata_proxy(rate_limited=False)

    def test_spawn_rate_limited_metadata_proxy(self):
        cfg.CONF.set_override('rate_limit_enabled', True,
                              group=meta_conf.RATE_LIMITING_GROUP)
        for k, v in self.RATE_LIMIT_CONFIG.items():
            cfg.CONF.set_override(k, v, group=meta_conf.RATE_LIMITING_GROUP)

        return self._test_spawn_metadata_proxy(rate_limited=True)

    def _test_spawn_metadata_proxy(self, rate_limited=False):
        datapath_id = _uuid()
        metadata_ns = metadata_agent.NS_PREFIX + datapath_id
        ip_class_path = 'neutron.agent.linux.ip_lib.IPWrapper'
        service_name = 'haproxy'

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
                service_name,
                '-f', cfg_file]

            log_tag = '{}-{}-{}'.format(
                service_name, metadata_driver.METADATA_SERVICE_NAME,
                datapath_id)

            expected_params = {
                'user': self.EUNAME,
                'group': self.EGNAME,
                'host': self.METADATA_DEFAULT_IP,
                'port': self.METADATA_PORT,
                'unix_socket_path': self.METADATA_SOCKET,
                'res_type': 'Network',
                'res_id': datapath_id,
                'pidfile': self.PIDFILE,
                'log_level': 'debug',
                'log_tag': log_tag,
                'bind_v6_line': ''}

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
                    metadata_driver._UNLIMITED_CONFIG_TEMPLATE +
                    metadata_driver._HEADER_CONFIG_TEMPLATE)

            cfg_contents = expected_config_template % expected_params
            mock_open.assert_has_calls([
                mock.call(cfg_file, 'w'),
                mock.call().write(cfg_contents)],
                any_order=True)

            env = {ep.PROCESS_TAG: service_name + '-' + datapath_id}
            ip_mock.assert_has_calls([
                mock.call(namespace=metadata_ns),
                mock.call().netns.execute(netns_execute_args, addl_env=env,
                                          run_as_root=True)
            ])

    def test_create_config_file_wrong_user(self):
        with mock.patch('pwd.getpwnam', side_effect=KeyError):
            config = metadata_driver.HaproxyConfigurator(mock.ANY, mock.ANY,
                                                         mock.ANY, mock.ANY,
                                                         mock.ANY, self.EUNAME,
                                                         self.EGNAME, mock.ANY,
                                                         mock.ANY, mock.ANY)
            self.assertRaises(comm_meta.InvalidUserOrGroupException,
                              config.create_config_file)

    def test_create_config_file_wrong_group(self):
        with mock.patch('grp.getgrnam', side_effect=KeyError),\
                mock.patch('pwd.getpwnam',
                           return_value=test_utils.FakeUser(self.EUNAME)):
            config = metadata_driver.HaproxyConfigurator(mock.ANY, mock.ANY,
                                                         mock.ANY, mock.ANY,
                                                         mock.ANY, self.EUNAME,
                                                         self.EGNAME, mock.ANY,
                                                         mock.ANY, mock.ANY)
            self.assertRaises(comm_meta.InvalidUserOrGroupException,
                              config.create_config_file)
