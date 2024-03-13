# Copyright 2017 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import collections
from unittest import mock

from oslo_config import cfg
from oslo_config import fixture as config_fixture
from oslo_utils import fileutils
import testtools
import webob

from neutron.agent.linux import utils as agent_utils
from neutron.agent.metadata import proxy_base
from neutron.agent.ovn.metadata import server as agent
from neutron.conf.agent.metadata import config as meta_conf
from neutron.tests import base

OvnPortInfo = collections.namedtuple(
        'OvnPortInfo', ['external_ids', 'chassis', 'mac', 'uuid'])


class ConfFixture(config_fixture.Config):
    pass


class TestMetadataProxyHandler(base.BaseTestCase):
    fake_conf = cfg.CONF
    fake_conf_fixture = ConfFixture(fake_conf)

    def setUp(self):
        super(TestMetadataProxyHandler, self).setUp()
        self.useFixture(self.fake_conf_fixture)
        self.log_p = mock.patch.object(proxy_base, 'LOG')
        self.log = self.log_p.start()
        self.agent_log_p = mock.patch.object(agent, 'LOG')
        self.agent_log = self.agent_log_p.start()
        self.handler = agent.MetadataProxyHandler(self.fake_conf, 'chassis1',
                                                  mock.Mock())
        self.handler._post_fork_event.set()

    def test_call(self):
        req = mock.Mock()
        with mock.patch.object(self.handler,
                               '_get_instance_and_project_id') as get_ids:
            get_ids.return_value = ('instance_id', 'project_id')
            with mock.patch.object(self.handler, '_proxy_request') as proxy:
                proxy.return_value = 'value'

                retval = self.handler(req)
                self.assertEqual(retval, 'value')

    def test_call_no_instance_match(self):
        req = mock.Mock()
        with mock.patch.object(self.handler,
                               '_get_instance_and_project_id') as get_ids:
            get_ids.return_value = None, None
            retval = self.handler(req)
            self.assertIsInstance(retval, webob.exc.HTTPNotFound)

    def test_call_internal_server_error(self):
        req = mock.Mock()
        with mock.patch.object(self.handler,
                               '_get_instance_and_project_id') as get_ids:
            get_ids.side_effect = Exception
            retval = self.handler(req)
            self.assertIsInstance(retval, webob.exc.HTTPInternalServerError)
            self.assertEqual(len(self.log.mock_calls), 2)

    def _get_instance_and_project_id_helper(self, forwarded_for, ports,
                                            mac=None, all_ports=False):
        network_id = 'the_id'
        headers = {
            'X-Forwarded-For': forwarded_for,
            'X-OVN-Network-ID': network_id
        }

        req = mock.Mock(headers=headers)

        def mock_get_network_port_bindings_by_ip(*args, **kwargs):
            if all_ports:
                return ports
            return ports.pop(0)

        self.handler.sb_idl.get_network_port_bindings_by_ip.side_effect = (
            mock_get_network_port_bindings_by_ip)

        instance_id, project_id = (
            self.handler._get_instance_and_project_id(req))

        expected = [mock.call(network_id, forwarded_for, mac=mac)]
        self.handler.sb_idl.get_network_port_bindings_by_ip.assert_has_calls(
            expected)
        return (instance_id, project_id)

    def test_get_instance_id_network_id_ipv4(self):
        forwarded_for = '192.168.1.1'
        mac = 'fa:16:3e:12:34:56'
        ovn_port = OvnPortInfo(
            external_ids={'neutron:device_id': 'device_id',
                          'neutron:project_id': 'project_id'},
            chassis=['chassis1'],
            mac=mac,
            uuid=1)
        ports = [[ovn_port]]

        self.assertEqual(
            self._get_instance_and_project_id_helper(forwarded_for, ports),
            ('device_id', 'project_id')
        )

    def test_get_instance_id_network_id_ipv6(self):
        forwarded_for = '2001:db8::1'
        mac = 'fa:16:3e:12:34:56'
        ovn_port = OvnPortInfo(
            external_ids={'neutron:device_id': 'device_id',
                          'neutron:project_id': 'project_id'},
            chassis=['chassis1'],
            mac=mac,
            uuid=1)
        ports = [[ovn_port]]

        self.assertEqual(
            self._get_instance_and_project_id_helper(forwarded_for, ports),
            ('device_id', 'project_id')
        )

    def test_get_instance_id_network_id_ipv6_ll(self):
        forwarded_for = 'fe80::99'
        # This is the EUI encoded MAC based on the IPv6 address
        forwarded_mac = '02:00:00:00:00:99'
        ovn_port = OvnPortInfo(
            external_ids={'neutron:device_id': 'device_id',
                          'neutron:project_id': 'project_id'},
            chassis=['chassis1'],
            mac=forwarded_mac,
            uuid=1)
        ports = [[ovn_port]]

        # IPv6 and link-local, the MAC will be passed
        self.assertEqual(
            self._get_instance_and_project_id_helper(forwarded_for, ports,
                                                     mac=forwarded_mac),
            ('device_id', 'project_id')
        )

    def test_get_instance_id_network_id_no_match(self):
        forwarded_for = '192.168.1.1'
        ports = [[]]

        expected = (None, None)
        observed = self._get_instance_and_project_id_helper(forwarded_for,
                                                            ports)
        self.assertEqual(expected, observed)
        self.assertEqual(len(self.agent_log.mock_calls), 1)

    def test_get_instance_id_network_id_too_many(self):
        forwarded_for = '192.168.1.1'
        mac = 'fa:16:3e:12:34:56'
        ovn_port_1 = OvnPortInfo(
            external_ids={'neutron:device_id': 'device_id',
                          'neutron:project_id': 'project_id'},
            chassis=['chassis1'],
            mac=mac,
            uuid=1)
        ovn_port_2 = OvnPortInfo(
            external_ids={'neutron:device_id': 'device_id',
                          'neutron:project_id': 'project_id'},
            chassis=['chassis2'],
            mac=mac,
            uuid=2)
        ports = [ovn_port_1, ovn_port_2]

        expected = (None, None)
        observed = self._get_instance_and_project_id_helper(forwarded_for,
                                                            ports,
                                                            all_ports=True)
        self.assertEqual(expected, observed)
        self.assertEqual(len(self.agent_log.mock_calls), 1)


class TestUnixDomainMetadataProxy(base.BaseTestCase):
    def setUp(self):
        super(TestUnixDomainMetadataProxy, self).setUp()
        self.cfg_p = mock.patch.object(agent, 'cfg')
        self.cfg = self.cfg_p.start()
        self.cfg.CONF.metadata_proxy_socket = '/the/path'
        self.cfg.CONF.metadata_workers = 0
        self.cfg.CONF.metadata_backlog = 128
        self.cfg.CONF.metadata_proxy_socket_mode = meta_conf.USER_MODE

    @mock.patch.object(fileutils, 'ensure_tree')
    def test_init_doesnot_exists(self, ensure_dir):
        agent.UnixDomainMetadataProxy(mock.Mock(), 'chassis1')
        ensure_dir.assert_called_once_with('/the', mode=0o755)

    def test_init_exists(self):
        with mock.patch('os.path.isdir') as isdir:
            with mock.patch('os.unlink') as unlink:
                isdir.return_value = True
                agent.UnixDomainMetadataProxy(mock.Mock(), 'chassis1')
                unlink.assert_called_once_with('/the/path')

    def test_init_exists_unlink_no_file(self):
        with mock.patch('os.path.isdir') as isdir:
            with mock.patch('os.unlink') as unlink:
                with mock.patch('os.path.exists') as exists:
                    isdir.return_value = True
                    exists.return_value = False
                    unlink.side_effect = OSError

                    agent.UnixDomainMetadataProxy(mock.Mock(), 'chassis1')
                    unlink.assert_called_once_with('/the/path')

    def test_init_exists_unlink_fails_file_still_exists(self):
        with mock.patch('os.path.isdir') as isdir:
            with mock.patch('os.unlink') as unlink:
                with mock.patch('os.path.exists') as exists:
                    isdir.return_value = True
                    exists.return_value = True
                    unlink.side_effect = OSError

                    with testtools.ExpectedException(OSError):
                        agent.UnixDomainMetadataProxy(mock.Mock(), 'chassis1')
                    unlink.assert_called_once_with('/the/path')

    @mock.patch.object(agent, 'MetadataProxyHandler')
    @mock.patch.object(agent_utils, 'UnixDomainWSGIServer')
    @mock.patch.object(fileutils, 'ensure_tree')
    def test_run(self, ensure_dir, server, handler):
        p = agent.UnixDomainMetadataProxy(self.cfg.CONF, 'chassis1')
        p.run()

        ensure_dir.assert_called_once_with('/the', mode=0o755)
        server.assert_has_calls([
            mock.call('neutron-ovn-metadata-agent'),
            mock.call().start(handler.return_value,
                              '/the/path', workers=0,
                              backlog=128, mode=0o644)]
        )
