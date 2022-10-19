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
from neutron.agent.ovn.metadata import server as agent
from neutron.common import utils as common_utils
from neutron.conf.agent.metadata import config as meta_conf
from neutron.conf.agent.ovn.metadata import config as ovn_meta_conf
from neutron.tests import base

OvnPortInfo = collections.namedtuple(
        'OvnPortInfo', ['external_ids', 'chassis'])


class ConfFixture(config_fixture.Config):
    def setUp(self):
        super(ConfFixture, self).setUp()
        ovn_meta_conf.register_meta_conf_opts(
            meta_conf.METADATA_PROXY_HANDLER_OPTS, self.conf)
        self.config(auth_ca_cert=None,
                    nova_metadata_host='9.9.9.9',
                    nova_metadata_port=8775,
                    metadata_proxy_shared_secret='secret',
                    nova_metadata_protocol='http',
                    nova_metadata_insecure=True,
                    nova_client_cert='nova_cert',
                    nova_client_priv_key='nova_priv_key')


class TestMetadataProxyHandler(base.BaseTestCase):
    fake_conf = cfg.CONF
    fake_conf_fixture = ConfFixture(fake_conf)

    def setUp(self):
        super(TestMetadataProxyHandler, self).setUp()
        self.useFixture(self.fake_conf_fixture)
        self.log_p = mock.patch.object(agent, 'LOG')
        self.log = self.log_p.start()
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

    def _get_instance_and_project_id_helper(self, headers, list_ports_retval,
                                            network=None):
        remote_address = '192.168.1.1'
        headers['X-Forwarded-For'] = remote_address
        req = mock.Mock(headers=headers)

        def mock_get_network_port_bindings_by_ip(*args, **kwargs):
            return list_ports_retval.pop(0)

        self.handler.sb_idl.get_network_port_bindings_by_ip.side_effect = (
            mock_get_network_port_bindings_by_ip)

        instance_id, project_id = (
            self.handler._get_instance_and_project_id(req))

        expected = [mock.call(network, '192.168.1.1')]
        self.handler.sb_idl.get_network_port_bindings_by_ip.assert_has_calls(
            expected)
        return (instance_id, project_id)

    def test_get_instance_id_network_id(self):
        network_id = 'the_id'
        headers = {
            'X-OVN-Network-ID': network_id
        }

        ovn_port = OvnPortInfo(
            external_ids={'neutron:device_id': 'device_id',
                          'neutron:project_id': 'project_id'},
            chassis=['chassis1'])
        ports = [[ovn_port]]

        self.assertEqual(
            self._get_instance_and_project_id_helper(headers, ports,
                                                     network='the_id'),
            ('device_id', 'project_id')
        )

    def test_get_instance_id_network_id_no_match(self):
        network_id = 'the_id'
        headers = {
            'X-OVN-Network-ID': network_id
        }

        ports = [[]]

        expected = (None, None)
        observed = self._get_instance_and_project_id_helper(headers, ports,
                                                            network='the_id')
        self.assertEqual(expected, observed)

    def _proxy_request_test_helper(self, response_code=200, method='GET'):
        hdrs = {'X-Forwarded-For': '8.8.8.8'}
        body = 'body'

        req = mock.Mock(path_info='/the_path', query_string='', headers=hdrs,
                        method=method, body=body)
        resp = mock.MagicMock(status_code=response_code)
        resp.status.__str__.side_effect = AttributeError
        resp.content = 'content'
        req.response = resp
        with mock.patch.object(common_utils, 'sign_instance_id') as sign:
            sign.return_value = 'signed'
            with mock.patch('requests.request') as mock_request:
                resp.headers = {'content-type': 'text/plain'}
                mock_request.return_value = resp
                retval = self.handler._proxy_request('the_id', 'tenant_id',
                                                     req)
                mock_request.assert_called_once_with(
                    method=method, url='http://9.9.9.9:8775/the_path',
                    headers={
                        'X-Forwarded-For': '8.8.8.8',
                        'X-Instance-ID-Signature': 'signed',
                        'X-Instance-ID': 'the_id',
                        'X-Tenant-ID': 'tenant_id'
                    },
                    data=body,
                    cert=(self.fake_conf.nova_client_cert,
                          self.fake_conf.nova_client_priv_key),
                    verify=False)

                return retval

    def test_proxy_request_post(self):
        response = self._proxy_request_test_helper(method='POST')
        self.assertEqual(response.content_type, "text/plain")
        self.assertEqual(response.body, 'content')

    def test_proxy_request_200(self):
        response = self._proxy_request_test_helper(200)
        self.assertEqual(response.content_type, "text/plain")
        self.assertEqual(response.body, 'content')

    def test_proxy_request_400(self):
        self.assertIsInstance(self._proxy_request_test_helper(400),
                              webob.exc.HTTPBadRequest)

    def test_proxy_request_403(self):
        self.assertIsInstance(self._proxy_request_test_helper(403),
                              webob.exc.HTTPForbidden)

    def test_proxy_request_404(self):
        self.assertIsInstance(self._proxy_request_test_helper(404),
                              webob.exc.HTTPNotFound)

    def test_proxy_request_409(self):
        self.assertIsInstance(self._proxy_request_test_helper(409),
                              webob.exc.HTTPConflict)

    def test_proxy_request_500(self):
        self.assertIsInstance(self._proxy_request_test_helper(500),
                              webob.exc.HTTPInternalServerError)

    def test_proxy_request_other_code(self):
        with testtools.ExpectedException(Exception):
            self._proxy_request_test_helper(302)


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
