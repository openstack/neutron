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

import io
import socketserver
from unittest import mock

from oslo_config import cfg
from oslo_config import fixture as config_fixture
import webob

from neutron.agent.metadata import proxy_base
from neutron.agent.ovn.metadata import server_socket as agent
from neutron.common import metadata as common_metadata
from neutron.tests import base


class ConfFixture(config_fixture.Config):
    pass


class TestMetadataProxyHandler(base.BaseTestCase):
    fake_conf = cfg.CONF
    fake_conf_fixture = ConfFixture(fake_conf)

    def setUp(self):
        super().setUp()
        self.useFixture(self.fake_conf_fixture)
        self.log_p = mock.patch.object(proxy_base, 'LOG')
        self.log = self.log_p.start()
        self.agent_log_p = mock.patch.object(agent, 'LOG')
        self.agent_log = self.agent_log_p.start()
        self.sb_idl = mock.Mock()
        agent.MetadataProxyHandler._conf = self.fake_conf
        agent.MetadataProxyHandler._chassis = 'chassis1'
        agent.MetadataProxyHandler._sb_idl = self.sb_idl
        self.mock_bytesio = mock.patch.object(io, 'BytesIO').start()
        self.mock_fromfile = mock.patch.object(
            webob.Request, 'from_file').start()
        self.mock_sfile = mock.patch.object(
            socketserver, '_SocketWriter').start()

    def test_call(self):
        req = mock.Mock()
        with mock.patch.object(agent.MetadataProxyHandler,
                               '_get_instance_and_project_id') as get_ids, \
                mock.patch.object(agent.MetadataProxyHandler,
                                  '_proxy_request') as proxy:
            get_ids.return_value = ('instance_id', 'project_id')
            proxy.return_value = 'value'
            agent.MetadataProxyHandler(req, 'client_address', 'server')
            self.mock_sfile.return_value.write.assert_called_once_with('value')

    def test_call_no_instance_match(self):
        req = mock.Mock()
        with mock.patch.object(agent.MetadataProxyHandler,
                               '_get_instance_and_project_id') as get_ids, \
                mock.patch.object(agent.MetadataProxyHandler,
                                  '_proxy_request'), \
                mock.patch.object(agent.MetadataProxyHandler,
                                  '_get_instance_id') as get_id:
            get_ids.return_value = None, None
            get_id.return_value = 'net_id', None
            agent.MetadataProxyHandler(req, 'client_address', 'server')
            title = '404 Not Found'
            msg = 'Instance was not found on network net_id.'
            response = common_metadata.encode_http_reponse(title, title, msg)
            self.mock_sfile.return_value.write.assert_called_once_with(
                response)

    def test_call_internal_server_error(self):
        req = mock.Mock()
        with mock.patch.object(agent.MetadataProxyHandler,
                               '_get_instance_and_project_id') as get_ids:
            get_ids.side_effect = RuntimeError
            self.assertRaises(RuntimeError,
                              agent.MetadataProxyHandler,
                              req, 'client_address', 'server')

    def test__get_instance_id_network_id_ipv4(self):
        req = mock.Mock(headers={'X-Forwarded-For': '192.168.1.1',
                                 'X-OVN-Network-ID': 'net_id'})
        self.mock_fromfile.return_value = req
        with mock.patch.object(agent.MetadataProxyHandler,
                               'get_port') as get_port, \
                mock.patch.object(agent.MetadataProxyHandler,
                                  '_proxy_request'):
            get_port.return_value = ('device_id', 'project_id')
            agent.MetadataProxyHandler(req, 'client_address', 'server')
            get_port.assert_called_once_with('192.168.1.1',
                                             network_id='net_id',
                                             remote_mac=None,
                                             router_id=None,
                                             skip_cache=False)

    def test__get_instance_id_network_id_ipv6(self):
        req = mock.Mock(headers={'X-Forwarded-For': '2001:db8::1',
                                 'X-OVN-Network-ID': 'net_id'})
        self.mock_fromfile.return_value = req
        with mock.patch.object(agent.MetadataProxyHandler,
                               'get_port') as get_port, \
                mock.patch.object(agent.MetadataProxyHandler,
                                  '_proxy_request'):
            get_port.return_value = ('device_id', 'project_id')
            agent.MetadataProxyHandler(req, 'client_address', 'server')
            get_port.assert_called_once_with('2001:db8::1',
                                             network_id='net_id',
                                             remote_mac=None,
                                             router_id=None,
                                             skip_cache=False)

    def test__get_instance_id_network_id_ipv6_ll(self):
        req = mock.Mock(headers={'X-Forwarded-For': 'fe80::99',
                                 'X-OVN-Network-ID': 'net_id'})
        self.mock_fromfile.return_value = req
        with mock.patch.object(agent.MetadataProxyHandler,
                               'get_port') as get_port, \
                mock.patch.object(agent.MetadataProxyHandler,
                                  '_proxy_request'):
            get_port.return_value = ('device_id', 'project_id')
            agent.MetadataProxyHandler(req, 'client_address', 'server')
            get_port.assert_called_once_with('fe80::99',
                                             network_id='net_id',
                                             remote_mac='02:00:00:00:00:99',
                                             router_id=None,
                                             skip_cache=False)
